# Tatu

An alternative Minecraft protocol providing cross-server identity without auth servers, sound transport encryption, lower latency, and better performance over poor network links.

This is a reference implementation as a Rust proxy. Protocol could be implemented directly in Fabric/Java. Specification: [PROTOCOL.md](PROTOCOL.md)

> [!WARNING]
> Work in progress. Protocol is unstable and subject to change. Documentation may not reflect the current state of the codebase.

## Status

- [x] Identity:
  - [x] Nick#disc handles
  - [x] Static UUIDs
  - [ ] Skin/cape uploads (needs specification)
- [x] Authentication:
  - [x] Client authentication
  - [x] Server identity, pinning
    - [ ] Show server identities in chat
  - [ ] Handle claim caching
- [x] Transport encryption:
  - [x] Noise XX
  - [ ] Fast Noise KK for known servers
- [ ] Session resumption
- [ ] Heterogeneous reliability

### Known bugs

- [ ] Sometimes, replicated only twice--once on long-distance teleportation and immediately on login--we get `Connection handler error: Noise encrypt: input error`.
- [ ] Server prints "Connection handler error: unexpected end of file" instead of player left.
