//! Packet batching utilities for reducing RTT by bundling multiple Minecraft packets
//! into a single TCP segment.

use azalea::protocol::packets::ProtocolPacket;
use azalea::protocol::write::{encode_to_network_packet, serialize_packet};
use std::fmt::Debug;
use std::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// A helper for batching multiple Minecraft protocol packets into a single TCP write.
///
/// With TCP_NODELAY enabled, each packet write creates a separate TCP segment.
/// This wastes round trips during handshake sequences. PacketBatch allows combining
/// multiple packets into one segment.
pub struct PacketBatch {
    buffer: Vec<u8>,
}

impl PacketBatch {
    /// Create a new empty packet batch.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    /// Add a packet to the batch.
    ///
    /// The packet will be serialized and framed (with length prefix), but not yet sent.
    pub fn add<P: ProtocolPacket + Debug>(
        mut self,
        packet: impl azalea::protocol::packets::Packet<P>,
    ) -> io::Result<Self> {
        let packet_variant = packet.into_variant();
        let serialized = serialize_packet(&packet_variant)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Encode with proper framing (length prefix)
        // Note: compression and encryption are handled at a different layer
        let network_packet = encode_to_network_packet(&serialized, None, &mut None);

        self.buffer.extend_from_slice(&network_packet);
        Ok(self)
    }

    /// Write all batched packets to the stream in a single operation.
    ///
    /// This ensures TCP sends them in one segment, reducing round trips.
    pub async fn write(self, stream: &mut TcpStream) -> io::Result<()> {
        if !self.buffer.is_empty() {
            stream.write_all(&self.buffer).await?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }
}

impl Default for PacketBatch {
    fn default() -> Self {
        Self::new()
    }
}
