# Tatu Protocol Specification

## 1. Overview

Tatu is a proxy protocol for Minecraft providing:
- Encrypted transport (Noise Protocol Framework)
- Cryptographic authentication (Ed25519)
- Cross-server persistent identity
- 1-RTT session resumption
- Fast reconnection with handle pinning

The protocol sits between Minecraft client and server, wrapping the existing Minecraft protocol with authenticated encryption and identity services.

## 2. Identity System

### 2.1. Design Goals

**Minecraft protocol constraints**:
- Usernames: maximum 16 characters
- UUIDs: 128 bits
  - (Minecraft Protocol does ask for the player UUID in the handshake packet, however it is then promptly ignored. Instead BungeeCord protocol is used to forward the UUID, available in any Spigot-derived server.
- While Minecraft primarily uses UUID to identify players, name collisions within one session may cause undefined behaviour, as Mojang traditionally enforces a unique name policy, break slash commands, as well as risk player impersonation.

**Identity requirements**:
- **Globally unique**: Same identity recognized across all Tatu servers
- **Verifiable**: Any server can verify identity claims independently without a central authority
- **Human-readable**: Users can communicate their identity verbally
- **Impersonation-resistant**: Costly to forge another user's identity

Unlike server passwords or client certificates manually mapped to names, which work only locally and require per-server setup, Tatu provides deterministic, verifiable, human-friendly handles derived from a user's keypair.

A user can prove they hold "alice#xkcd1234" to any Tatu server without them coordinating or consulting an external registry.

### 2.2. Terminology

- **Identity**: Ed25519 keypair (signing key, verify key) _belonging to a player_, holding a handle and UUID, used for signatures and authentication
- **Server key**: An X25519 keypair used for transport authentication.
- **Nick**: User-chosen short name (e.g., "alice")
- **Discriminator**: See §2.3
- **Handle**: Full username nick#discriminator (e.g., "alice#xkcd1234")
- **UUID**: 128-bit hash of Ed25519 public key (persistent across servers)

### 2.3. Handle Format

```
handle := nick#discriminator
  where:
    discriminator := [a-z]{4}[0-9]{4}        // Always 8 characters
    nick := [a-zA-Z0-9_]{1,7}                // Max 7 chars, truncated if needed
    len(handle) ≤ 16

Examples:
  alice#xkcd1234      (14 chars)
  alexand#dead8337    (16 chars, truncated from "alexander")
```

**Discriminator**: An 8-character encoding of a time-locked signature over the nick
- Proves ~60 seconds of sequential computation was performed (VDF)
- Cryptographically binds nick to identity keypair
- Format: 4 lowercase letters + 4 digits (e.g., "xkcd1234")
- Cannot be chosen by user, only discovered through computation

**Design rationale**:
- **32-bit namespace**: 26^4 * 10^4 = 4.57 billion discriminators
  - Sufficient for identity uniqueness, assuming sufficient nick entropy
  - Insufficient for combinatorial security (brute-forceable without cost)
  - Requires time-lock to prevent impersonation attacks (§2.4)
- **Ambiguity resistance**: Separate letter and digit sections eliminate 0/O confusion
- **Memorability**: Human-friendly compared to hex/base32/base58

### 2.4. Discriminator Derivation

The discriminator is an identity signature over nick ran through a Verifiable Delay Function (VDF) to prevent impersonations attacks.

**Why VDF is necessary**: Without sequential cost, the 32-bit discriminator space (~4.57B) is vulnerable to:
- Targeted attack: Finding a specific discriminator takes 2^31 attempts, parallelizable to minutes on GPUs
- Vanity mining: Attackers can exhaust desirable discriminators (e.g., "aaaa0000")
- Namespace pollution: Mass-claiming discriminators for DoS

**VDF construction** (Wesolowski over RSA-2048):
- Sequential computation: y = x^(2^T) mod N, where T = 2^23 squarings (~60 seconds)
- Cannot be parallelized (inherent to modular exponentiation)
- Fast verification: ~15ms using Wesolowski proof pi
- Parameters: N = RSA-2048 challenge modulus, T = 2^23 iterations, proof size ~512 bytes
- Security: Targeted impersonation requires 2^31 × 60s = ~4000 CPU years of sequential computation

**Client derivation process** (performed ONCE, cached indefinitely):
```
Client computes:
  1. Choose nick (e.g., "alice")
  2. Generate Ed25519 keypair (signing_key, verify_key)
  3. signature = Ed25519.sign(signing_key, nick)

  4. x = H(nick || signature) mod (N-1) + 1
  5. y = VDF(x, T, N)
  6. pi = Wesolowski.prove(x, y, T, N)

  7. discriminator = format_disc(H(y))
  8. uuid = BLAKE2b-256(verify_key)[0..16]  // Raw 128 bits, NOT RFC 4122

Discriminator encoding:
  hash = BLAKE2b(y, digest_size=4)
  letters = [hash[i] % 26 -> 'a'..'z'] for i in [0..4)
  digits  = [hash[i] % 10 -> '0'..'9'] for i in [4..8)
  discriminator = letters + digits

Identity bundle (cached locally):
  - ed25519_keypair: (signing_key, verify_key)
  - nick: String
  - nick_signature: [u8; 64]
  - vdf_output: BigInt (y)
  - vdf_proof: BigInt (pi)
  - discriminator: String (derived)
```

This bundle is computed once and reused across all servers and all sessions.
The VDF proof is deterministic and non-interactive, requiring no server coordination.

**Server verification**:
```
Server receives: (nick, nick_signature, ed25519_pubkey, vdf_output, vdf_proof)

Verification steps:
  1. Verify nick signature:
     Ed25519.verify(ed25519_pubkey, nick, nick_signature)  // Proves key ownership

  2. Recompute VDF input:
     x = H(nick || nick_signature) mod (N-1) + 1

  3. Verify VDF proof:
     Wesolowski.verify(x, vdf_output, vdf_proof, T, N)     // Proves sequential work

  4. Derive discriminator:
     discriminator = format(H(vdf_output))

  5. Derive UUID:
     uuid = BLAKE2b-256(ed25519_pubkey)[0..16]  // Raw 128 bits, NOT RFC 4122
```

**Security properties**:
- **Non-choosable**: User cannot select discriminator, only discover it
- **Deterministic**: Same (nick, identity) always yields same discriminator
- **Collision-resistant**: Different identities -> different signatures -> different discriminators
- **Time-locked**: Each discriminator derivation requires ~60 seconds sequential work
- **Verifiable**: Any server can verify the discriminator-to-identity binding independently

### 2.5. Collision Analysis

The discriminator provides 32 bits of entropy (26^4 * 10^4 ~= 2^32). Combined with nickname diversity, this creates a compound namespace resistant to accidental collisions at community scale.

**Empirical uniqueness**: Analysis of 730 Discord-Minecraft username pairs shows:

* Unique base nicknames: 625/730 = 85.62%
* Most common base appears 7 times (0.96%)
* Shannon entropy from nicknames alone: 9.18 bits

This captures real-world naming patterns: users select memorable but moderately varied nicknames.

**Collision probability model**:

For a population of n users with nickname uniqueness rate u and discriminator bits d:

```
P(collision) = 1 - exp(-n / (2u * 2^d))
Where u = 0.8562, d = 32 bits
```

| Population (n) | P(collision) | Expected Collisions | Deployment Scale |
| -------------- | ------------ | ------------------- | ---------------- |
| 100K           | 0.0014%      | 0.00                | Large server     |
| 5M             | 0.0680%      | 0.00                | 5x 2b2t total    |
| 50M            | 0.6776%      | 0.01                | Modded MC        |
| 100M           | 1.3505%      | 0.01                | Java MC upper    |

**Design rationale**: For community-scale servers (1M–10M users), expected collisions remain very low (<0.1%). In the rare case of a collision, servers use handle pinning (TOFU) to resolve handle conflicts (see §3.2).

### 2.6. Portable Keyfiles

**Keyfiles are the ONLY portable format between implementations.** All other data (VDF proofs, claims, pins, session state) is implementation-specific.

**Format**: Raw 32 bytes, no encoding, no headers
- Client identity: Ed25519 private key seed
- Server key: Curve25519/X25519 private scalar
- Permissions: Mode 0600 (readable only by owner)

Same keyfile produces the same public key, UUID, and handle across all implementations.

## 3. Authentication Protocol

Tatu supports two authentication modes:

1. **Regular login (Noise_XX)**: Full VDF verification for first-time connections
2. **Fast login (Noise_KK)**: Optimized reconnection using handle pinning and cached keys

### 3.1. Regular Login (Noise_XX + VDF Verification)

**Used when**: Client connects to server for the first time, or when server doesn't have client's identity pinned.

**Noise configuration**: `Noise_XX_25519_ChaChaPoly_BLAKE2b`

The Noise XX pattern provides mutual authentication through static key exchange:

**Client prerequisites** (performed ONCE at identity creation, see §2.4):
- Identity bundle already computed and cached locally
- Contains: ed25519_keypair, nick, nick_signature, vdf_output, vdf_proof, discriminator, uuid
- Ed25519 keypair is used as Noise static keypair (25519 keys are compatible)
- No computation needed on connection, simply load from cache

**Handshake** (Noise_XX pattern):
```
-> e
<- e, ee, s, es
-> s, se, ENCRYPTED[Claim {
     nick: String,
     nick_signature: [u8; 64],
     vdf_output: BigInt,
     vdf_proof: BigInt,
   }]
```

The third message (`-> s, se`) transmits the client's static Ed25519 public key via Noise, which serves double-duty:
- Noise static key for transport encryption and mutual authentication
- Identity verification key for nick signature and discriminator binding

**Server verification** (see §2.4 for details):
1. Extract client_static_key from Noise handshake (this is the Ed25519 public key)
2. Verify `Ed25519.verify(client_static_key, nick, nick_signature)`
3. Recompute `x = H(nick || nick_signature) mod (N-1) + 1`
4. Verify Wesolowski proof: `pi^l * x^r ≡ y (mod N)` (~15ms)
5. Derive `discriminator = format(H(y))`
6. Derive `handle = nick#discriminator`
7. Derive UUID: `uuid = BLAKE2b-256(client_static_key)[0..16]`

**Server response**: Continues with Minecraft login/configuration packets (see §4.2)

**Client finalizes**:
- Store server_static_key for future Noise_KK connections (TOFU pinning)
- Client may now use Noise_KK for subsequent connections (see §3.2)

**Rejection reasons**:
- Invalid Ed25519 signature (nick not signed by claimed key)
- Invalid VDF proof (failed Wesolowski verification)

**Security properties**:
- **Mutual authentication**: Both parties prove knowledge of their static keys
- **Forward secrecy**: Ephemeral keys in messages 1-2 provide PFS
- **Replay protection**: Noise transport inherently prevents replays
- **No oracle attacks**: Challenge-response eliminated, Noise handles all authentication

**Cost**: 1.5 RTT handshake + VDF verification (~15ms server-side)

### 3.2. Fast Login (Noise_KK + Handle Pinning)

**Used when**: Client and server have both cached each other's static keys from a previous Noise_XX handshake.

**Noise configuration**: `Noise_KK_25519_ChaChaPoly_BLAKE2b`

**Prerequisites**:
- Client has pinned server_static_key (from previous XX handshake)
- Server knows client's static key (from previous XX handshake)

**Handshake** (Noise_KK pattern):
```
-> e, es, ss, ENCRYPTED[KKPayload {
     handle: String,                  // "alice#xkcd1234"
     last_seq_sent: Option<u64>,      // For session resumption (§3.3)
     last_seq_received: Option<u64>,
   }]
<- e, ee, se, ENCRYPTED[login/config packets or resume confirmation]
```

**Server processing**:
1. Extract client_static_key from Noise pre-shared knowledge
2. Receive handle from encrypted payload
3. **Handle pinning (TOFU)**:
   - If `handle -> client_static_key` pin exists: verify it matches
   - If pin exists with different key: **REJECT** (potential impersonation)
   - If no pin exists: create pin `handle -> client_static_key`
4. Derive `uuid = BLAKE2b-256(client_static_key)[0..16]`
5. If resumption requested (§3.3): validate and attempt resume
6. Otherwise: proceed with fresh Minecraft login

**Benefits over Noise_XX**:
- **1-RTT handshake** (vs 1.5-RTT for XX)
- **No VDF proof transmission** (~512 bytes saved)
- **No VDF verification** (~15ms server computation saved)
- **Fully encrypted from first message** (metadata protection)
- **Enables session resumption** (see §3.3)

**Rejection reasons**:
- Server doesn't recognize client_static_key (no prior XX handshake)
- Handle pinned to different client_static_key (potential impersonation)
- Incorrect server key (possible MitM)

**Fallback**: On rejection, client MUST fall back to Noise_XX handshake with full VDF proof.

**Security**: Server MUST NOT accept Noise_XX without full VDF verification, even for known clients. Noise_KK and Noise_XX use separate authentication paths.

### 3.3. Session Resumption (1-RTT Reconnection)

**Goal**: Allow clients to resume interrupted sessions without re-logging to Minecraft server, achieving 1-RTT recovery from temporary network failures.

**Mechanism**: Client tracks sequence numbers of sent/received packets. On reconnection via Noise_KK, client includes last known sequence numbers.

**Resume validation** (server-side):

If last_seq_sent is present:
  1. Extract timestamp: hint_ts = last_seq_sent >> 32
  2. Reject if expired: (server_time - hint_ts) > 300 seconds
  3. Reject if not monotonic: last_seq_sent ≤ session.last_seq_sent
  4. Reject if clock skew: |hint_ts - server_time| > 60 seconds
  5. Otherwise: resume if session exists, else fresh login


**On successful resume**:
- Server keeps Minecraft socket alive (player never logged out in-game)
- Server flushes buffered packets (queued during disconnect, max 1000 packets or 10 MB)
- Server responds with buffered packets and resumes bidirectional forwarding
- Client receives buffered packets and continues game state

**On failed resume** (session expired, not found, or validation failed):
- Server closes any stale Minecraft socket
- Server responds with fresh login/configuration packets
- Client performs full Minecraft login sequence

**Benefits**:
- **Seamless recovery**: Player doesn't disconnect in-game during brief network hiccups
- **1-RTT restore**: Single round trip to resume forwarding
- **Bandwidth efficient**: No re-transmission of login/configuration data

**Security**: Server MUST limit buffered packets during disconnect (e.g., 1000 packets or 10 MB) to prevent memory exhaustion attacks.

### 3.4. Sequence Numbers

All game packets are framed with sequence numbers after Noise encryption:

```
message := control_byte || payload

control_byte:
  0x00 = game packet
  0x01 = resume acknowledgment (server -> client, contains buffered packets)
  0x02..0xFF = reserved for future use

game_packet := seq_num || minecraft_packet
  where:
    seq_num := u64 big-endian = (timestamp << 32) | counter
    timestamp := u32 (UNIX seconds)
    counter := u32 (monotonic message counter within that second)
    minecraft_packet := opaque bytes (Minecraft protocol)
```

**Properties**:
- Strictly monotonic within a session
- Timestamp provides implicit session age and timeout
- Clock skew detection: reject if `|message_timestamp - server_time| > 60 seconds`
- Session resumption: validate timestamp continuity (reject if gap > 300 seconds)
- Direction tracking: client and server maintain independent counters

**Note**: Replay protection is provided by Noise protocol tags. Sequence numbers are primarily for session resumption validation and detecting stale connections.

## 4. Minecraft Protocol Integration

Tatu acts as a proxy between unmodified Minecraft client and server, wrapping packets in Noise encryption and modifying login credentials. During the login/configuration phase, the proxy intercepts and buffers packets to enable bundling optimization (§4.2). After configuration completes, the proxy operates transparently, forwarding all gameplay packets without inspection.

### 4.1. Packet Rewriting

**Handshake packet** (0x00): Modified to use BungeeCord forwarding protocol
```
Original hostname format:
  {hostname, port, protocol_version, next_state}

Modified with BungeeCord forwarding:
  hostname = "original_hostname\0client_ip\0derived_uuid\0[]"

Example:
  "play.example.com\01.2.3.4\0550e8400-e29b-41d4-a716-446655440000\0[]"
```

This allows the backend Minecraft server to:
- Receive the Tatu-derived UUID without intercepting Login Success packets
- Log the original client IP address for moderation
- Work with any Spigot-derived server (standard BungeeCord protocol)

**Login Start** (-> Minecraft server):
```
Original:  {username: "alice"}
Modified:  {username: "alice#xkcd1234"}
```

**Other packets**: See §4.2 for login/configuration bundling. After configuration, gameplay packets are treated as opaque blobs and forwarded without inspection.

### 4.2. Bundled Login/Configuration Optimization

**Goal**: Compress Minecraft login/configuration into minimal TCP writes, achieving 1-RTT login.

**Minecraft 1.20.2+ login phases**:
```
Phase 1: Login
  <- Login Success (UUID, username, properties)

Phase 2: Configuration
  <- ClientboundRegistryDataPacket (registries, tags, etc.)
  <- ClientboundUpdateEnabledFeaturesPacket
  <- ClientboundCustomPayload (resource packs, plugins)
  <- ... (5-15 configuration packets)
  <- ClientboundFinishConfigurationPacket
  -> ServerboundFinishConfigurationPacket (ack)

Phase 3: Play
  <- ClientboundLoginPacket (dimension, gamemode, spawn, etc.)
```

**Bundling strategy**: After Noise handshake completes, Tatu server proxy intercepts and buffers all Minecraft server packets during login/configuration phase. Upon detecting ClientboundFinishConfigurationPacket, proxy sends entire bundle as single Noise-encrypted blob. This requires protocol-aware state tracking during configuration.

**Packet format**:
```
Bundled payload = Login Success || Registry Data || Features || ... || Finish Config

Where || denotes concatenation of length-prefixed Minecraft packets:
  packet := varint(length) || packet_id || packet_data

The bundled payload is:
  1. Wrapped in sequence number framing (§3.4)
  2. Wrapped in Noise encryption (chunked at 65KB boundaries as needed)
  3. Sent via single write_all() to ensure TCP coalescing

TCP_NODELAY MUST be enabled on all Tatu connections to prevent Nagle's algorithm from delaying small packets.
```

**Implementation**: Tatu server proxy parses Minecraft protocol during configuration to identify packet boundaries and detect ClientboundFinishConfigurationPacket. Proxy buffers all packets (LoginSuccess, RegistryData, UpdateEnabledFeatures, ..., FinishConfiguration), concatenates them as length-prefixed packets, then sends via single write operation through Noise channel.

**Client handling**: Tatu client proxy MUST read and decrypt bundled payload, parse individual length-prefixed Minecraft packets sequentially, process Login Success and Configuration packets in order, then may synthesize or forward ServerboundFinishConfigurationPacket ack to backend, then transition to transparent forwarding for Play phase.

**Trade-off**: Bundling requires protocol-aware proxies that track Minecraft state during login/configuration. This complexity enables 1-RTT login but breaks strict transparency during this phase.

**Performance gains**:
- Unbundled: ~15-20 TCP segments (3-5 RTT)
- Noise_XX bundled: 4 segments (~1.5 RTT)
- Noise_KK bundled: **2 segments (1 RTT)** from TCP connect to gameplay
