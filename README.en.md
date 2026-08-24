# VRCPersona Internals

[日本語](./README.md)

Parts of VRCPersona's internal implementation, published so they can be read.

**This is the code from VRCPersona v1.0.0.** Credential encryption was added in v1.0.0; v0.7.6 and earlier do not have it (see [Target version](#target-version)).

---

## What is included

| Area | Contents | Source |
|---|---|---|
| credential-storage | Storage and encryption of VRChat credentials | [`src/credential-storage/`](./src/credential-storage/) |

**Anything not listed above cannot be verified from this repository.** This is not the full app
source; it is limited to the areas in the table. For example, what the app transmits using those
credentials cannot be determined here.

These files also **do not build**. This is a repository to read, not a working crate.

---

# credential-storage

Where and how VRCPersona stores your VRChat credentials.

## Target version

The files in this repository are from **VRCPersona v1.0.0**.

Credential encryption was added in v1.0.0. In v0.7.6 and earlier, these files were stored as
plaintext JSON. After updating to v1.0.0, existing plaintext files are re-saved encrypted when they
are read (`decode_or_migrate`).

## What is stored

Everything is stored on the user's own PC. Nothing is sent to VRCPersona's servers.

On Windows, the files are located in:

```
%APPDATA%\com.sasaken1102s.vrcpersona\
```

| File | Contents | Encrypted |
|---|---|---|
| `cookies.json` | VRChat auth cookies (`auth` / `twoFactorAuth`) | Yes |
| `cookies_<userId>.json` | Cookie backup used for account switching | Yes |
| `saved_accounts.json` | Account information for quick login | Yes |
| `pronouns_restore.json` | Restore data for pronouns temporarily changed during VRChat identity verification | Yes |

`saved_accounts.json` holds six fields per account (see `SavedAccount` in `storage.rs`):

- `user_id` — VRChat user ID
- `display_name` — display name
- `thumbnail_url` — thumbnail image URL
- `auth_token` — authentication token
- `saved_at` / `last_login_at` — timestamps

The auth token for the currently signed-in account is also stored in the OS credential manager
(see `save_auth_token` in `storage.rs`, entry name `vrchat_auth_token`).

Email addresses and passwords are not stored. They are only passed to the VRChat API at sign-in time.
Token login, which requires no password entry, is the recommended method.

## How it is protected

The implementation is in `secure_store.rs`.

- **Cipher** — ChaCha20-Poly1305 (RustCrypto, pure Rust)
- **Master key** — 256-bit, generated with `getrandom` and stored in the OS keychain
  (Windows Credential Manager)
  - keyring entry name: `vrcpersona_master_key`
  - The service name is the app identifier, so development and release builds use separate keys
- **File format** — magic header `VPENC1` (6 bytes) + random nonce (12 bytes) + ciphertext
  (+ 16-byte authentication tag)
  - A fresh nonce is generated per encryption, so identical content produces different ciphertext
  - The authentication tag causes decryption to fail if the data has been modified
- **Migration from older versions** — when an unencrypted file is detected, it is read and then
  re-saved encrypted (`decode_or_migrate`)

These behaviors are covered by the unit tests at the end of `secure_store.rs`.

## What this does not protect against

From the comment at the top of `secure_store.rs` (the source comment is in Japanese; translated here):

> Local encryption mainly defends against "copy the file and read it elsewhere" style threats.
> Because the master key lives in the OS keychain, malware running under the same user account can
> decrypt it via the keychain — a residual risk this design does not prevent.

Malware already running with the same privileges as the user is not prevented by this scheme.

What this encryption addresses is malware that scans JSON files under `%APPDATA%` to extract
authentication tokens.

## About auth tokens

VRChat auth cookies are bound to the IP address they were issued to and cannot be used from a
different IP.

- [VRChat Creator Guidelines](https://hello.vrchat.com/creator-guidelines) (updated 2025-04-15)
  — "If a user account is interacting with our API, we assume that the interaction comes from the
  user's device and IP."
- [VRChat Feedback — login fails when the IP changes per connection](https://feedback.vrchat.com/bug-reports/p/workaround-found-cloudflare-warp-blocks-login-and-causes-error-since-feb-27-2026)
  (reported 2026-02-28, marked "Tracked" by VRChat on 2026-03-11)
  — a changing source IP produces `authToken doesn't correspond with an active session`; pinning the
  IP resolves it
- [Response from the official VRChat account](https://feedback.vrchat.com/feature-requests/p/allow-authcookie-to-be-used-from-a-different-ip-address-extra-features) (2020-02-18)
  — describes the measure as being aimed at stolen tokens

A token can be revoked at any time by signing out on the VRChat website.

A token can perform the same operations against the VRChat API as a password login, because both
paths end up using the same auth token. The benefit of token login is not reduced scope; it is that
no password is handed over, and a leaked token cannot be reused elsewhere.

See the [FAQ](https://vrcpersona.sasaken1102s.net/faqs/#token-login) for sources (Japanese only for now).

---

## About this repository

- These files are identical to the ones in `src-tauri/src/` of VRCPersona v1.0.0
- They are updated here when the implementation changes
- This is not a buildable crate

## License

[GPLv3](./LICENSE)

VRCPersona itself is closed-source software, and its [Terms of Use](https://vrcpersona.sasaken1102s.net/terms/)
prohibit modification, copying and redistribution. **The files in this repository are an exception.**
As the copyright holder, these files — and only these files — are licensed under GPLv3 for use,
modification and redistribution. This does not extend to any other part of the app.

## Issues / Pull Requests

See [CONTRIBUTING.md](./CONTRIBUTING.md).
Issues are accepted. Code pull requests are not.

## Links

- Website: https://vrcpersona.sasaken1102s.net/
- FAQ (Japanese): https://vrcpersona.sasaken1102s.net/faqs/
- Privacy Policy: https://vrcpersona.sasaken1102s.net/en/privacy/
