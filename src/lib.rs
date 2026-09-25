#![forbid(unsafe_code)]

//! A file only the Service Identity can read, as the key home's store
//! (ADR-0063 clause 4): Linux, and every Unix.
//!
//! A key-encryption key is thirty-two random bytes in
//! `<directory>/<name>.kek`, the file `0600` and the directory `0700`, both
//! owned by the effective user this process runs as. A key found with wider
//! permissions, or another owner, is refused as [`SecretError::Exposed`]
//! and not used: a key others could have read is a key others could have
//! copied, and saying so is better than sealing under it.
//!
//! The bytes are the key as it is. The protection is the operating system's
//! ownership and mode, and the disk's own encryption where the machine has
//! it; a key that must never be readable as bytes belongs in a hardware
//! module (the `pkcs11` technology, reserved).
//!
//! The Linux kernel keyring is not used for this. It holds a key until the
//! machine restarts, and a key-encryption key lost at a restart is every
//! record it sealed, lost (`architecture.toml`, `secret.keyring`).
//!
//! [`KeyFile`] is a [`secret::KekHolder`]; wrap it in [`secret::Held`] for a
//! [`secret::KeyStore`]. Unix only: on Windows this crate is empty, and
//! `dpapi` is the store there.

#[cfg(unix)]
use secret::{KekHolder, KekName, SecretError, Store};
#[cfg(unix)]
use std::fs::{self, DirBuilder, Metadata, OpenOptions};
#[cfg(unix)]
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use zeroize::Zeroizing;

/// The permission bits a key file or its directory may not have: any for
/// the group, any for others.
#[cfg(unix)]
const WIDER: u32 = 0o077;

/// Key-encryption keys as private files in one private directory.
#[cfg(unix)]
pub struct KeyFile {
    directory: PathBuf,
}

#[cfg(unix)]
impl KeyFile {
    /// A store keeping its keys in `directory`, created `0700` when the
    /// first key is.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path(&self, name: &KekName) -> PathBuf {
        self.directory.join(format!("{name}.kek"))
    }
}

/// Refuses `path` unless this process's effective user owns it and neither
/// the group nor others have any permission on it.
#[cfg(unix)]
fn private(path: &Path, metadata: &Metadata) -> Result<(), SecretError> {
    let mode = metadata.mode() & 0o777;
    let me = rustix::process::geteuid().as_raw();
    if mode & WIDER != 0 || metadata.uid() != me {
        return Err(SecretError::Exposed {
            what: format!(
                "{} is mode {mode:o} owned by user {}; a key needs mode {} owned by user {me}",
                path.display(),
                metadata.uid(),
                if metadata.is_dir() { "700" } else { "600" },
            ),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn failed(path: &Path, error: &std::io::Error) -> SecretError {
    SecretError::store(format!("{}: {error}", path.display()))
}

#[cfg(unix)]
impl KekHolder for KeyFile {
    fn store(&self) -> Store {
        Store {
            technology: "file",
            place: self.directory.display().to_string(),
        }
    }

    fn read(&self, name: &KekName) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        let path = self.path(name);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failed(&path, &error)),
        };
        let parent = fs::metadata(&self.directory).map_err(|e| failed(&self.directory, &e))?;
        private(&self.directory, &parent)?;
        private(&path, &metadata)?;
        fs::read(&path)
            .map(|key| Some(Zeroizing::new(key)))
            .map_err(|error| failed(&path, &error))
    }

    fn create(&self, name: &KekName, material: &[u8]) -> Result<(), SecretError> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.directory)
            .map_err(|error| failed(&self.directory, &error))?;
        // An existing directory keeps its mode: it is checked, not changed.
        let parent = fs::metadata(&self.directory).map_err(|e| failed(&self.directory, &e))?;
        private(&self.directory, &parent)?;
        let path = self.path(name);
        // create_new: a key already there is never replaced (KekHolder).
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| failed(&path, &error))?;
        file.write_all(material)
            .and_then(|()| file.sync_all())
            .map_err(|error| failed(&path, &error))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use secret::{DataKey, Held, KeyStore};
    use std::os::unix::fs::PermissionsExt;

    fn directory(test: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("xmip-secret-file-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path.join("key")
    }

    fn name(text: &str) -> KekName {
        KekName::new(text).expect("name")
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn a_key_wraps_and_unwraps_through_a_private_file() {
        let dir = directory("round");
        let store = Held::new(KeyFile::new(&dir));
        let key = DataKey::generate().expect("key");
        let wrapped = store.wrap(&name("runtime"), &key).expect("wrapped");
        let again = Held::new(KeyFile::new(&dir));
        let back = again.unwrap(&name("runtime"), &wrapped).expect("unwrapped");
        let sealed = key.seal(b"a", b"payload").expect("sealed");
        assert_eq!(back.open(b"a", &sealed).expect("opened"), b"payload");
        let mode = fs::metadata(dir.join("runtime.kek")).expect("file").mode() & 0o777;
        assert_eq!(mode, 0o600);
        let mode = fs::metadata(&dir).expect("dir").mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_missing_key_is_refused_by_name() {
        let dir = directory("missing");
        let store = Held::new(KeyFile::new(&dir));
        let refused = store.unwrap(&name("absent"), &[0; 60]);
        let Err(SecretError::MissingKek { name, store: place }) = refused else {
            panic!("expected MissingKek, got {refused:?}");
        };
        assert_eq!(name, "absent");
        assert!(place.starts_with("file at "), "{place}");
    }

    #[test]
    fn a_key_file_others_can_read_is_refused() {
        let dir = directory("wide-file");
        let holder = KeyFile::new(&dir);
        holder.create(&name("k"), &[1u8; 32]).expect("created");
        chmod(&dir.join("k.kek"), 0o644);
        let refused = holder.read(&name("k"));
        assert!(
            matches!(refused, Err(SecretError::Exposed { .. })),
            "{refused:?}"
        );
    }

    #[test]
    fn a_key_directory_others_can_enter_is_refused() {
        let dir = directory("wide-dir");
        let holder = KeyFile::new(&dir);
        holder.create(&name("k"), &[1u8; 32]).expect("created");
        chmod(&dir, 0o755);
        assert!(matches!(
            holder.read(&name("k")),
            Err(SecretError::Exposed { .. })
        ));
        assert!(matches!(
            holder.create(&name("other"), &[1u8; 32]),
            Err(SecretError::Exposed { .. })
        ));
    }

    #[test]
    fn an_existing_key_is_never_replaced() {
        let dir = directory("replace");
        let holder = KeyFile::new(&dir);
        holder.create(&name("k"), &[1u8; 32]).expect("created");
        assert!(holder.create(&name("k"), &[2u8; 32]).is_err());
        let kept = holder.read(&name("k")).expect("read").expect("held");
        assert_eq!(kept.as_slice(), &[1u8; 32]);
    }
}
