#pragma once

// ATTENTION
// ---------
// When updating this file, make sure to update doc/comm.rst as well because it
// copies parts of this file verbatim.
//
// Included lines: 26-37

#include <string>
#include <utility>

#include <caf/message.hpp>
#include <caf/make_message.hpp>

#include "broker/endpoint_info.hh"

#include "broker/detail/operators.hh"
#include "broker/detail/type_traits.hh"

namespace broker {

/// Broker's status codes.
/// @relates status
enum class sc : uint8_t {
  /// The unspecified default error code.
  unspecified = 0,
  /// Successfully added a new peer.
  peer_added,
  /// Successfully removed a peer.
  peer_removed,
  /// Lost connection to peer.
  peer_lost,
};

/// @relates sc
const char* to_string(sc code);

/// Diagnostic status information.
class status : detail::equality_comparable<status, status>,
               detail::equality_comparable<status, sc>,
               detail::equality_comparable<sc, status> {

public:
  template <sc S>
  static detail::enable_if_t<S == sc::unspecified, status>
  make(std::string msg) {
    status s;
    s.code_ = S;
    if (!msg.empty())
      s.context_ = caf::make_message(std::move(msg));
    return s;
  }

  template <sc S>
  static detail::enable_if_t<
    S == sc::peer_added
    || S == sc::peer_removed
    || S == sc::peer_lost,
    status
  >
  make(endpoint_info ei, std::string msg) {
    status s;
    s.code_ = S;
    s.context_ = caf::make_message(std::move(ei), std::move(msg));
    return s;
  }

  /// Default-constructs an unspecified status.
  status() = default;

  /// @returns The code of this status.
  sc code() const;

  /// Retrieves additional contextual information, if available.
  /// The [status code][::sc] determines the type of information that's
  /// available.
  /// @tparam T The type of the attached context information.
  template <class T>
  const T* context() const {
    switch (code_) {
      default:
        return nullptr;
      case sc::peer_added:
      case sc::peer_removed:
      case sc::peer_lost:
        return &context_.get_as<endpoint_info>(0);
    }
  }

  /// Retrieves an optional details about the status, if available.
  /// @returns A textual description of status details.
  const std::string* message() const;

  friend bool operator==(const status& x, const status& y);

  friend bool operator==(const status& x, sc y);

  friend bool operator==(sc x, const status& y);

  friend std::string to_string(const status& s);

  template <class Inspector>
  friend typename Inspector::result_type inspect(Inspector& f, status& s) {
    return f(s.code_, s.context_);
  }

private:
  sc code_ = {};
  caf::message context_;
};

template <sc S, class... Ts>
status make_status(Ts&&... xs) {
  return status::make<S>(std::forward<Ts>(xs)...);
}

} // namespace broker
