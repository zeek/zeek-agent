#pragma once

#include <caf/atom.hpp>

namespace broker {

using atom_value = caf::atom_value;

template <atom_value V>
using atom_constant = caf::atom_constant<V>;

namespace atom {

/// Creates an atom from given string literal.
template <size_t Size>
constexpr atom_value make(char const (&str)[Size]) {
     return caf::atom(str);
}

/// --- inherited from CAF -----------------------------------------------------

using add = caf::add_atom;
using get = caf::get_atom;
using join = caf::join_atom;
using leave = caf::leave_atom;
using ok = caf::ok_atom;
using put = caf::put_atom;
using connect = caf::connect_atom;
using subscribe = caf::subscribe_atom;
using unsubscribe = caf::unsubscribe_atom;
using tick = caf::tick_atom;
using publish = caf::publish_atom;
using update = caf::update_atom;

/// --- generic communication --------------------------------------------------

using name = caf::atom_constant<caf::atom("name")>;
using network = caf::atom_constant<caf::atom("network")>;
using peer = caf::atom_constant<caf::atom("peer")>;
using status = caf::atom_constant<caf::atom("status")>;
using unpeer = caf::atom_constant<caf::atom("unpeer")>;
using default_ = caf::atom_constant<caf::atom("default")>;
using shutdown = caf::atom_constant<caf::atom("shutdown")>;
using retry = caf::atom_constant<caf::atom("retry")>;

/// --- communication with workers ---------------------------------------------

using resume = caf::atom_constant<caf::atom("resume")>;

/// --- communication with stores ----------------------------------------------

using attach = caf::atom_constant<caf::atom("attach")>;
using clear = caf::atom_constant<caf::atom("clear")>;
using clone = caf::atom_constant<caf::atom("clone")>;
using decrement = caf::atom_constant<caf::atom("decrement")>;
using erase = caf::atom_constant<caf::atom("erase")>;
using expire = caf::atom_constant<caf::atom("expire")>;
using exists = caf::atom_constant<caf::atom("exists")>;
using increment = caf::atom_constant<caf::atom("increment")>;
using keys = caf::atom_constant<caf::atom("keys")>;
using master = caf::atom_constant<caf::atom("master")>;
using store = caf::atom_constant<caf::atom("store")>;
using subtract = caf::atom_constant<caf::atom("subtract")>;
using local = caf::atom_constant<caf::atom("local")>;
using resolve = caf::atom_constant<caf::atom("resolve")>;
using stale_check = caf::atom_constant<caf::atom("stale")>;
using mutable_check = caf::atom_constant<caf::atom("mutable")>;
using sync_point = caf::atom_constant<caf::atom("sync_point")>;

/// --- communciation with core actor ------------------------------------------

using no_events = caf::atom_constant<caf::atom("noEvents")>;
using subscriptions = caf::atom_constant<caf::atom("subs")>;
using snapshot = caf::atom_constant<caf::atom("snapshot")>;

} // namespace atom
} // namespace broker
