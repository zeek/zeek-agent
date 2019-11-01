#pragma once

#include "broker/endpoint_info.hh"
#include "broker/peer_flags.hh"
#include "broker/peer_status.hh"

namespace broker {

/// Information about a peer of an endpoint.
/// @relates endpoint
struct peer_info {
  endpoint_info peer;   ///< Information about the peer.
  peer_flags flags;     ///< Details about peering relationship.
  peer_status status;   ///< The current peering status.
};

template <class Inspector>
typename Inspector::result_type inspect(Inspector& f, peer_info& pi) {
  return f(pi.peer, pi.flags, pi.status);
}

} // namespace broker
