# Tatu

An alternative Minecraft protocol providing cross-server identity without auth servers, sound transport encryption, lower latency, and better performance over poor network links.

This is a reference implementation as a Rust proxy. Protocol could be implemented directly in Fabric/Java. Specification: [PROTOCOL.md](PROTOCOL.md)

> [!WARNING]
> Work in progress. Protocol is unstable and subject to change. Documentation may not reflect the current state of the codebase.

## Status

**Identity**:
- [x] nick#disc timelocked handles
- [x] Persistent UUIDs w/ BungeeCord UUID forwarding
- [ ] Player skins (awaiting specification)

**Security**:
- [x] Noise_XX handshake
  - [x] Client authentication
  - [x] Server key pinning (TOFU)
- [ ] Noise_KK fast handshake
  - [ ] Server-side handle pinning

**Performance**:
- [ ] Bundled login/configuration (1-RTT)
- [ ] Session resumption (1-RTT reconnect)
  - [ ] Sequence number framing

