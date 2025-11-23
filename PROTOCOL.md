# Tatu Protocol Specification

## 1. Overview

Tatu is a proxy protocol for Minecraft providing:
- Encrypted transport (Noise Protocol Framework)
- Cryptographic authentication (Ed25519)
- Cross-server persistent identity
- 1-RTT session resumption
- Priority trees for fair bandwidth distribution?

The protocol sits between Minecraft client and server, wrapping the existing Minecraft protocol with authenticated encryption and identity services.

## 2. Identity System

### 2.1. Design Goals

**Minecraft protocol constraints**:
- Usernames: maximum 16 characters (hardcoded in protocol)
- UUIDs: 128 bits
  - FOR SOME GOD FORSAKEN REASON, MINECRAFT IGNORES UUIDS COMPLETELY IN OFFLINE MODE! YOU CAN CHANGE YOUR UUID IN THE LOGIN PACKET AND IT WILL JUST IGNORE IT; YOUR UUID CAN JUST NOT MATCH THE ONE ON THE SERVER, AND EVERYTHING IS PAIN
  >  UUID.nameUUIDFromBytes(("OfflinePlayer:" + player).getBytes(UTF_8))
- Both username and UUID must fit in login handshake packets

**Identity requirements**:
- **Globally unique**: Same identity recognized across all Tatu servers
- **Verifiable**: Any server can verify identity claims independently without a central authority
- **Human-readable**: Users can communicate their identity verbally
- **Impersonation-resistant**: Costly to forge another user's identity

Unlike server passwords or client certificates manually mapped to names, which work only locally and require per-server setup, Tatu provides deterministic, verifiable, human-friendly handles derived from a user's keypair.

A user can prove they hold "alice#xkcd1234" to any Tatu server without them coordinating or consulting an external registry.

### 2.2. Terminology

- **Identity**: Ed25519 keypair (signing key, verify key)
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
- Vanity mining: Attackers can exhaust desirable discriminators (e.g., "aaaa0000"), vastly increasing the likelihood of collisions
- Namespace pollution: Mass-claiming discriminators for DoS (e.g. exploiting the server's handle-key pin to block a nick from joining)

**VDF construction** (Wesolowski over RSA-2048):
- **Sequential computation**: y = x^(2^T) mod N, where T = 2^23 squarings (~60 +- 5 seconds)
- **Cannot be parallelized**: No GPU/distributed speedup (inherent to modular exponentiation)
- **Fast verification**: ~15ms using Wesolowski proof π
- **Parameters**:
  - N = RSA-2048 challenge modulus (2048 bits, remains unfactored)
  - T = 2^23 iterations (~8.4 million squarings)
  - Proof size: ~512 bytes

**Security budget**:
- Legitimate user: 60 seconds once, identity used indefinitely
- Targeted impersonation: 2^31 × 60s = ~4000 CPU years (each attempt is NOT splittable, occupying one thread per attempt)
- Economic barrier: requires sequential high-power CPU time, not parallelizable over low-power botnets

**Client derivation process** (performed ONCE, cached indefinitely):
```
Client computes:
  1. Choose nick (e.g., "alice")
  2. Generate Ed25519 keypair (signing_key, verify_key)
  3. signature = Ed25519.sign(signing_key, nick)

  4. x = H(nick || signature) mod (N-1) + 1
  5. y = VDF(x, T, N)
  6. π = Wesolowski.prove(x, y, T, N)

  7. discriminator = format_disc(H(y))
  8. uuid = BLAKE2b-256(verify_key)[0..16]

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
  - vdf_proof: BigInt (π)
  - discriminator: String (derived)
  - uuid: [u8; 16] (derived)
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
     uuid = BLAKE2b-256(ed25519_pubkey)[0..16]
```

**Security properties**:
- **Non-choosable**: User cannot select discriminator, only discover it
- **Deterministic**: Same (nick, identity) always yields same discriminator
- **Collision-resistant**: Different identities -> different signatures -> different discriminators
- **Time-locked**: Each discriminator derivation requires ~60 seconds sequential work
- **Verifiable**: Any server can verify the discriminator-to-identity binding independently

**Discriminator pinning** (optional server optimization):
- Servers SHOULD pin first claim: discriminator -> pubkey (TOFU model)
- Subsequent logins: if discriminator pinned, verify pubkey matches (skip VDF verification)
- Saves bandwidth (~512 bytes proof) and computation (~15ms verification) on repeat logins
- For cross-server scenarios: users preshare pubkeys or UUIDs out-of-band (server whitelists)

**Key insight**: The VDF proof is non-interactive and deterministic. A client computes it once (at identity creation) and caches it forever. The same proof is reused across all servers and all sessions without modification.


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

**Design rationale**: For community-scale servers (1M–10M users), expected collisions remain very low (<0.1%). In the rare case of a collision, servers SHOULD use discriminator pinning (TOFU) to resolve handle conflicts.

## 3. Authentication Protocol

### 3.1. First Connection (Noise_XX + VDF)

**Noise configuration**: Noise_XX_25519_ChaChaPoly_BLAKE2s

**Client prerequisites** (performed ONCE at identity creation, see §2.4):
- Identity bundle already computed and cached locally
- Contains: keypair, nick, nick_signature, vdf_output, vdf_proof, discriminator, uuid
- No computation needed on connection, simply load from cache

**Handshake**:
```
-> e
<- e, ee, s, es
-> s, se, ENCRYPTED[{
     nick: String,
     nick_signature: [u8; 64],
     vdf_output: BigInt,
     vdf_proof: BigInt,
   }]
<- ENCRYPTED[{status, uuid}]
```

**Server verification** (see §2.4 for details):
1. Extract client_pubkey from Noise handshake
2. Verify Ed25519.verify(client_pubkey, nick, nick_signature)
3. Recompute x = H(nick || nick_signature) mod (N-1) + 1
4. Verify Wesolowski proof: π^l * x^r ≡ y (mod N)  (~15ms)
5. Derive discriminator = format(H(y))
6. Check pin: if discriminator exists, require matching pubkey
7. Store: client_pubkey -> (nick, discriminator, uuid)
8. Respond with {status: "accepted", uuid}

**Client finalizes**:
- Store server_pubkey for future Noise_KK connections

**Rejection reasons**:
- Invalid Ed25519 signature (nick not signed by claimed key)
- Invalid VDF proof
- Discriminator pinned to different pubkey

### 3.2. Subsequent Connection (Noise_KK)

**Noise configuration**: Noise_KK_25519_ChaChaPoly_BLAKE2s

**Handshake**:
```
-> e, es, ss, ENCRYPTED[{
     last_seq_sent: u64,      // Optional: for session resumption
     last_seq_received: u64,
   }]
<- e, ee, se, ENCRYPTED[{status, uuid, nick, discriminator}]
```

**Server processing**:
1. Extract client_pubkey from Noise
2. Lookup identity: client_pubkey -> (nick, discriminator, uuid)
3. Respond with identity confirmation

**Client state**:
- Client stores server_pubkey after first connection (§3.1)
- Reuses same server_pubkey for all future connections to this server

### 3.3. Session Resumption (Optional Extension)

If the client includes sequence numbers in the KK handshake payload, the server MAY attempt to resume an existing session instead of starting fresh.

**Resume validation**:
- Extract timestamp: hint_ts = last_seq_sent >> 32
- Reject if expired: (server_time - hint_ts) > 300 seconds
- Reject if not monotonic: last_seq_sent ≤ session.last_seq
- Reject if clock skew: |hint_ts - server_time| > 60 seconds
- Otherwise: resume if session exists, else fresh login

**On successful resume**:
- Server keeps Minecraft socket alive (player never left game)
- Server flushes buffered packets (queued during disconnect, max 1000 packets or 10 MB)
- Server responds: {status: "resumed", next_seq, buffered_packets[]}
- Bidirectional forwarding resumes

**On failed resume**:
- Server closes any stale Minecraft socket
- Server responds: {status: "fresh", uuid, nick, discriminator}
- Client performs full Minecraft login sequence

### 3.4. Sequence Numbers

All game packets are framed with sequence numbers after Noise encryption:

```
message := control_byte || payload

control_byte:
  0x00 = game packet
  0x01..0xFF = reserved for future use

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
- Clock skew detection: reject if |message_timestamp - server_time| > 60 seconds
- Session resumption: validate timestamp continuity (reject if gap > 300 seconds)
- Direction parity: client uses even counters, server uses odd

## 4. Minecraft Protocol Integration

Tatu acts as a transparent proxy between unmodified Minecraft client and server, wrapping packets in Noise encryption and rewriting login credentials.

### 4.1. Packet Rewriting

**Handshake packet** (0x00): Pass through unchanged
```
{server_address, server_port, protocol_version, next_state}
```

**Login Start** (Client -> Server):
```
Original:  {username: "alice"}
Modified:  {username: "alice#xkcd1234"}
```

**Login Success** (Server -> Client):
```
Original:  {uuid: mojang_uuid, username: "alice"}
Modified:  {uuid: derived_uuid, username: "alice#xkcd1234"}
```

**All other packets**: Treated as opaque blobs
- Proxies do not parse Minecraft packet internals
- Packets are framed, encrypted, sequenced, and forwarded transparently
