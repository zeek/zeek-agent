#pragma once

#include "broker/address.hh"

namespace broker {

/// An IPv4 or IPv6 subnet (an address prefix).
class subnet : detail::totally_ordered<subnet> {
public:
  /// Default construct empty subnet ::/0.
  subnet();

  /// Construct subnet from an address and length.
  subnet(address addr, uint8_t length);

  /// @return whether an address is contained within this subnet.
  bool contains(const address& addr) const;

  /// @return the network address of the subnet.
  const address& network() const;

  /// @return the prefix length of the subnet.
  uint8_t length() const;

  friend bool operator==(const subnet& lhs, const subnet& rhs);
  friend bool operator<(const subnet& lhs, const subnet& rhs);

  template <class Inspector>
  friend typename Inspector::result_type inspect(Inspector& f, subnet& sn) {
    return f(sn.net_, sn.len_);
  }

private:
  bool init();

  address net_;
  uint8_t len_;
};

/// @relates subnet
bool operator==(const subnet& lhs, const subnet& rhs);

/// @relates subnet
bool operator<(const subnet& lhs, const subnet& rhs);

/// @relates subnet
bool convert(const subnet& sn, std::string& str);

} // namespace broker

namespace std {
template <>
struct hash<broker::subnet> {
  size_t operator()(const broker::subnet&) const;
};
} // namespace std;
