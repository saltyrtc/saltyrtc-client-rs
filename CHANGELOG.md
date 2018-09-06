# Changelog

This project follows semantic versioning.

Possible log types:

- `[added]` for new features.
- `[changed]` for changes in existing functionality.
- `[deprecated]` for once-stable features removed in upcoming releases.
- `[removed]` for deprecated features removed in this release.
- `[fixed]` for any bug fixes.
- `[security]` to invite users to upgrade in case of vulnerabilities.


### v0.6.0 (2018-09-06)

- [added] New close code: 3008 timeout
- [fixed] Use thread-safe SaltyClient smart pointers in public APIs (#50)
- [changed] Upgrade `rust_sodium` to 0.10.0

### v0.5.0 (2018-08-07)

- [added] Create `SaltyClient::current_peer_sequence_numbers`
- [added] Create `SaltyClient::encrypt_raw_with_session_keys`
- [added] Create `SaltyClient::decrypt_raw_with_session_keys`
- [fixed] Remove duplicate trace log
- [changed] Upgrade some dependencies
- [changed] PeerContext: Replace `csn_pair` RefCell with RwLock

### v0.5.0-beta.3 (2018-06-01)

- [changed] Less strict close code validation (accept any u16)

### v0.5.0-beta.2 (2018-05-15)

- Upgrade `clippy` to 0.0.200
- Upgrade `rust_sodium` to 0.9.0

### v0.5.0-beta.1 (2018-05-15)

- First release on crates.io
