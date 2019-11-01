#pragma once

#include <cstdint>
#include <string>

#include "broker/detail/operators.hh"

namespace broker {

/// A transport-layer port.
class port : detail::totally_ordered<port> {
public:
  using number_type = uint16_t;

  enum class protocol : uint8_t {
    unknown,
    tcp,
    udp,
    icmp,
  };

  /// Default construct empty port, 0/unknown.
  port();

  /// Construct a port from number/protocol.
  port(number_type num, protocol p);

  /// @return The port number.
  number_type number() const;

  /// @return The port's transport protocol.
  protocol type() const;

  friend bool operator==(const port& lhs, const port& rhs);
  friend bool operator<(const port& lhs, const port& rhs);

  template <class Inspector>
  friend typename Inspector::result_type inspect(Inspector& f, port& p) {
    return f(p.num_, p.proto_);
  }

private:
  number_type num_;
  protocol proto_;
};

/// @relates port
bool operator==(const port& lhs, const port& rhs);

/// @relates port
bool operator<(const port& lhs, const port& rhs);

/// @relates port
bool convert(const port& p, std::string& str);

/// @relates port
bool convert(const std::string& str, port& p);

} // namespace broker

namespace std {
template <>
struct hash<broker::port> {
  size_t operator()(const broker::port&) const;
};
} // namespace std;
