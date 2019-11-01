#pragma once

#include <functional>

namespace broker {
namespace detail {

/// Calculate hash for an object and combine with a provided hash.
template <class T>
inline void hash_combine(size_t& seed, const T& v) {
  seed ^= std::hash<T>()(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

template <class It>
inline size_t hash_range(It first, It last) {
  size_t seed = 0;
  for (; first != last; ++first)
    hash_combine(seed, *first);
  return seed;
}

template <class It>
inline void hash_range(size_t& seed, It first, It last) {
  for (; first != last; ++first)
    hash_combine(seed, *first);
}

// Allows hashing of composite types.
template <class Container>
struct container_hasher {
  using result_type = size_t;

  result_type operator()(const Container& c) const {
    auto result = result_type{0};
    auto n = result_type{0};
    for (auto& e : c) {
      hash_combine(result, e);
      ++n;
    }
    hash_combine(result, n);
    return result;
  }
};

} // namespace detail
} // namespace broker
