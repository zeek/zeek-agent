#pragma once

#include <memory>

#include <xxhash.h>

namespace zeek {
struct XXH64StateDeleter final {
  using pointer = XXH64_state_t *;

  void operator()(XXH64_state_t *state) const;
};

using UniqueXXH64State =
    std::unique_ptr<XXH64StateDeleter::pointer, XXH64StateDeleter>;

UniqueXXH64State createXXH64State();
} // namespace zeek
