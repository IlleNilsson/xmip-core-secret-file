# xmip-core-secret-file

A file only the Service Identity can read, as the key home's store on Linux
and every Unix (ADR-0063 clause 4). A technology of
[xmip-core-secret](https://github.com/IlleNilsson/xmip-core-secret).

A key-encryption key is thirty-two random bytes in `<directory>/<name>.kek`,
the file `0600` and the directory `0700`, both owned by the effective user
the process runs as. A key or directory found wider, or owned by another
user, is refused as `SecretError::Exposed` and not used: a key others could
read is a key others could have copied. An existing directory is checked,
never changed. A key file is created once and never replaced.

The bytes are the key as it is; the protection is the operating system's
ownership and mode, and the disk's encryption where the machine has it. A key
that must never exist as readable bytes belongs in a hardware module (the
`pkcs11` technology, reserved).

**Why not the kernel keyring.** ADR-0063 names the Linux kernel keyring beside
this file. A key in the kernel keyring lasts until the machine restarts, and a
key-encryption key lost at a restart is every record it sealed, lost; so
`keyring` stays reserved in `architecture.toml` until the owner decides what
it is for.

`KeyFile` is a `secret::KekHolder`; `secret::Held::new(KeyFile::new(dir))` is
the `KeyStore`. On Windows the crate is empty. The effective user comes from
`rustix`, a safe call, so the crate keeps `unsafe_code = "forbid"`.

## Verification

Tested on the AlmaLinux guest: a key wraps and unwraps through the file, which
is `0600` in a `0700` directory; a missing key is refused by name; a key file
chmodded `0644` is refused as exposed; a directory chmodded `0755` is refused
for reading and for creating; an existing key is never replaced. The workflow
is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
