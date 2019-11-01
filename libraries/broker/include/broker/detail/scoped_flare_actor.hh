#pragma once

#include <caf/message.hpp>
#include <caf/actor_system.hpp>
#include <caf/scoped_execution_unit.hpp>

namespace broker {
namespace detail {

class flare_actor;

// A `scoped_actor` equipped with a descriptor suitable for poll/select
// loops that signals whether the actor's mailbox is emppty, i.e., whether the
// actor can receive messages without blocking.
class scoped_flare_actor {
public:
  template <class, class, int>
  friend class caf::actor_cast_access;

  static constexpr bool has_weak_ptr_semantics = false;
  static constexpr bool has_non_null_guarantee = true;

  scoped_flare_actor(caf::actor_system& sys);

  scoped_flare_actor(const scoped_flare_actor&) = delete;
  scoped_flare_actor(scoped_flare_actor&&) = default;

  ~scoped_flare_actor();

  scoped_flare_actor& operator=(const scoped_flare_actor&) = delete;
  scoped_flare_actor& operator=(scoped_flare_actor&&) = default;

  flare_actor* operator->() const;

  flare_actor& operator*() const;

  caf::actor_addr address() const;

  flare_actor* ptr() const;

  caf::message dequeue();

private:
  caf::actor_control_block* get() const;

  caf::scoped_execution_unit context_;
  caf::strong_actor_ptr self_;
};

} // namespace detail
} // namespace broker
