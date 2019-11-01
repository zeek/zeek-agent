#pragma once

#include <iostream>

namespace broker {
namespace detail {

template <class T>
void render(T&& x) {
  std::cerr << x;
}

template <class T, class... Ts>
void render(T&& x, Ts&&... xs) {
  render(std::forward<T>(x));
  std::cerr << " ";
  render(std::forward<Ts>(xs)...);
}

/// Terminates the process immediately with an error message
/// @param xs The arguments, rendered space-separated to standard error.
template <class... Ts>
[[noreturn]] void die(Ts&&... xs) {
  render(std::forward<Ts>(xs)...);
  std::cerr << std::endl;
  std::abort();
}

} // namespace detail
} // namespace broker
