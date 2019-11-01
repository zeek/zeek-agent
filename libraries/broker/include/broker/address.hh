#pragma once

#include <array>
#include <cstdint>
#include <string>

#include <broker/detail/operators.hh>

namespace broker {

/// Stores an IPv4 or IPv6 address.
class address : detail::totally_ordered<address> {
public:
  /// Distinguishes between address types.
  enum class family : uint8_t {
    ipv4,
    ipv6,
  };

  /// Distinguishes between address byte ordering.
  enum class byte_order : uint8_t {
    host,
    network,
  };

  /// Default construct an invalid address.
  address();

  /// Construct an address from raw bytes.
  /// @param bytes A pointer to the raw representation.  This must point
  /// to 4 bytes if *fam* is `family::ipv4` and 16 bytes for `family::ipv6`.
  /// @param fam The type of address.
  /// @param order The byte order in which *bytes* is stored.
  address(const uint32_t* bytes, family fam, byte_order order);

  /// Mask out lower bits of the address.
  /// @param top_bits_to_keep The number of bits to *not* mask out, counting
  /// from the highest order bit.  The value is always interpreted relative to
  /// the IPv6 bit width, even if the address is IPv4.  That means to compute
  /// 192.168.1.2/16, pass in 112 (i.e. 96 + 16).  The value must range from
  /// 0 to 128.
  /// @returns true on success.
  bool mask(uint8_t top_bits_to_keep);

  /// @returns true if the address is IPv4.
  bool is_v4() const;

  /// @returns true if the address is IPv6.
  bool is_v6() const;

  /// @returns the raw bytes of the address in network order. For IPv4
  /// addresses, this uses the IPv4-mapped IPv6 address representation.
  std::array<uint8_t, 16>& bytes();

  /// @returns the raw bytes of the address in network order. For IPv4
  /// addresses, this uses the IPv4-mapped IPv6 address representation.
  const std::array<uint8_t, 16>& bytes() const;

  friend bool operator==(const address& lhs, const address& rhs);
  friend bool operator<(const address& lhs, const address& rhs);
  friend bool convert(const std::string& str, address& a);

  template <class Inspector>
  friend typename Inspector::result_type inspect(Inspector& f, address& a) {
    return f(a.bytes_);
  }

private:
  std::array<uint8_t, 16> bytes_; // Always in network order.
};

/// @relates address
bool operator==(const address& lhs, const address& rhs);

/// @relates address
bool operator<(const address& lhs, const address& rhs);

/// @relates address
bool convert(const std::string& str, address& a);

/// @relates address
bool convert(const address& a, std::string& str);

} // namespace broker

namespace std {

/// @relates address
template <>
struct hash<broker::address> {
  size_t operator()(const broker::address&) const;
};

} // namespace std;
