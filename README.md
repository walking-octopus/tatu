# Tatu

Tatu is an alternative Minecraft authentication and encryption protocol. This repository contains its reference implementation as a Rust proxy, but it can also be implemented directly in Java.

Tatu provides players with a persistent, cross-server identity without relying on centralized authentication servers, while being as secure as--or more secure than--Mojang's `online-mode`.

- [x] Identity
    - [x] Weseloski VDF
    - [x] Ed25519-X25519 binding
    - [x] Discriminator encoding
    - [x] Key files
    - [ ] Recovery phrases
- [x] Noise Pipe
    - [x] Server key pinning
- [x] MessagePack wire
- [x] Minecraft forwarding, BungeeCord hostname
    - [ ] Skins
    - [ ] Inject client errors as Minecraft connection errors
    - [ ] Inject server key as client chat message
- [ ] v1 Specification

*Future work*
  - [ ] Fast Noise_KK handshake with known server key
        - [ ] Client key pinning
  - [ ] Stream management & 1RTT session resumption?
  - [ ] Protocol-aware flushing
  - [ ] Custom chunk wire with Hilbert curve ordering + zstd?

