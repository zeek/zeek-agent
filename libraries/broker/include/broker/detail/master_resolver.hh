#pragma once

#include <vector>

#include <caf/actor.hpp>
#include <caf/behavior.hpp>
#include <caf/stateful_actor.hpp>


namespace broker {
namespace detail {

struct master_resolver_state {
  size_t remaining_responses;
  caf::actor who_asked;
};

using master_resolver_actor = caf::stateful_actor<master_resolver_state>;

/// Queries each peer in `peers`.
caf::behavior master_resolver(master_resolver_actor* self);

} // namespace detail
} // namespace broker
