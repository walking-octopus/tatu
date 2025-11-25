# Tatu

An alternative Minecraft protocol providing cross-server identity without auth servers, sound transport encryption, lower latency, and better performance over poor network links.

This is a reference implementation as a Rust proxy. Protocol could be implemented directly in Fabric/Java. Specification: [PROTOCOL.md](PROTOCOL.md)

> [!WARNING]
> Work in progress. Protocol is unstable and subject to change.

## Status

- [x] Identity:
  - [x] Nick#disc handles
  - [x] Static UUIDs
  - [ ] Skin/cape uploads (needs specification)
- [x] Authentication:
  - [x] Client, server authentication
  - [ ] Handle claim pinning
  - [ ] Server pubkeys, pinning
  - [ ] Show server/peer pubkeys in chat
- [ ] Transport encryption:
  - [x] Noise XX introductory
  - [ ] Noise KK with known servers
- [ ] Session resumption
- [ ] Heterogeneous reliability
