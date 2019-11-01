#pragma once

#include <caf/node_id.hpp>

#include "broker/fwd.hh"
#include "broker/network_info.hh"
#include "broker/optional.hh"

namespace broker {

using caf::node_id;

/// Information about an endpoint.
/// @relates endpoint
struct endpoint_info {
  node_id node;                   ///< A unique context ID per machine/process.
  optional<network_info> network; ///< Optional network-level information.
};

template <class Inspector>
typename Inspector::result_type inspect(Inspector& f, endpoint_info& info) {
  return f(info.node, info.network);
}

} // namespace broker
