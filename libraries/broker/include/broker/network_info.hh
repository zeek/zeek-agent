#pragma once

#include <cstdint>
#include <string>

#include "broker/timeout.hh"
#include "broker/detail/operators.hh"

namespace broker {

/// Represents an IP address and TCP port combination.
struct network_info : detail::totally_ordered<network_info> {
  network_info() = default;
  network_info(std::string addr, uint16_t port,
               timeout::seconds retry = timeout::seconds());

  std::string address;
  uint16_t port;
  timeout::seconds retry;
};

/// @relates network_info
bool operator==(const network_info& x, const network_info& y);

/// @relates network_info
bool operator<(const network_info& x, const network_info& y);

/// @relates network_info
template <class Inspector>
typename Inspector::result_type inspect(Inspector& f, network_info& info) {
  return f(info.address, info.port, info.retry);
}

/// @relates network_info
inline std::string to_string(const network_info& info) {
  using std::to_string;
  return info.address + ':' + to_string(info.port);
}

} // namespace broker

namespace std {

template <>
struct hash<broker::network_info> {
  size_t operator()(const broker::network_info& x) const {
    hash<string> f;
    return f(x.address) ^ static_cast<size_t>(x.port);
  }
};

} // namespace std
