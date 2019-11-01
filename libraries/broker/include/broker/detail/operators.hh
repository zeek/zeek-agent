#pragma once

namespace broker {
namespace detail {

template <class T, class U = T>
struct equality_comparable {
  friend bool operator!=(const T& x, const U& y) {
    return !(x == y);
  }
};

template <class T, class U = T>
struct less_than_comparable {
  friend bool operator>(const T& x, const U& y) {
    return y < x;
  }

  friend bool operator<=(const T& x, const U& y) {
    return !(y < x);
  }

  friend bool operator>=(const T& x, const U& y) {
    return !(x < y);
  }
};

template <class T, class U = T>
struct totally_ordered : equality_comparable<T, U>,
                         less_than_comparable<T, U> {};

} // namespace detail
} // namespace broker
