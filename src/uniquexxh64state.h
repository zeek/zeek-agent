#pragma once

#include <memory>

#include <xxhash.h>

namespace zeek {
/// \brief A deleter functor for XXH64 states
struct XXH64StateDeleter final {
  using pointer = XXH64_state_t *;

  void operator()(XXH64_state_t *state) const;
};

/// \brief A unique_ptr wrapper for XXH64 states
using UniqueXXH64State =
    std::unique_ptr<XXH64StateDeleter::pointer, XXH64StateDeleter>;

/// \return Creates a new XXH64 state
UniqueXXH64State createXXH64State();
} // namespace zeek
