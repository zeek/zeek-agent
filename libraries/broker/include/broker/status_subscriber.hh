#pragma once

#include <vector>

#include <caf/actor.hpp>
#include <caf/variant.hpp>

#include "broker/error.hh"
#include "broker/fwd.hh"
#include "broker/status.hh"
#include "broker/subscriber_base.hh"
#include "broker/bad_variant_access.hh"

#include "broker/detail/shared_subscriber_queue.hh"

namespace broker {

using status_variant = caf::variant<none, error, status>;

/// Provides blocking access to a stream of endpoint events.
class status_subscriber
  : public subscriber_base<status_variant> {
public:
  // --- friend declarations ---------------------------------------------------

  friend class endpoint;

  // --- nested types ----------------------------------------------------------

  using super = subscriber_base<status_variant>;

  // --- constructors and destructors ------------------------------------------

  status_subscriber(status_subscriber&&) = default;

  status_subscriber& operator=(status_subscriber&&) = default;

  ~status_subscriber();

  inline const caf::actor& worker() const {
    return worker_;
  }

private:
  // -- force users to use `endpoint::make_status_subscriber` -------------------
  status_subscriber(endpoint& ep, bool receive_statuses = false);

  caf::actor worker_;
};

// --- compatibility/wrapper functionality (may be removed later) -----------

template <class T>
inline bool is(const status_variant& v) {
  return caf::holds_alternative<T>(v);
}

template <class T>
inline T* get_if(status_variant& d) {
  return caf::get_if<T>(&d);
}

template <class T>
inline const T* get_if(const status_variant& d) {
  return caf::get_if<T>(&d);
}

template <class T>
inline T& get(status_variant& d) {
  if ( auto rval = caf::get_if<T>(&d) )
    return *rval;
  throw bad_variant_access{};
}

template <class T>
inline const T& get(const status_variant& d) {
  if ( auto rval = caf::get_if<T>(&d) )
    return *rval;
  throw bad_variant_access{};
}

} // namespace broker
