#pragma once

namespace broker {

/// Describes the possible states of a peer. A local peer begins in state
/// `initialized` and transitions directly to `peered`. A remote peer
/// begins in `initialized` and then through states `connecting`, `connected`,
/// and then `peered`.
enum class peer_status {
  initialized,    ///< The peering process has been initiated.
  connecting,     ///< Connection establishment is in progress.
  connected,      ///< Connection has been established, peering pending.
  peered,         ///< Successfully peering.
  disconnected,   ///< Connection to remote peer lost.
  reconnecting,   ///< Reconnecting after a lost connection.
};

const char* to_string(peer_status);

} // namespace broker
