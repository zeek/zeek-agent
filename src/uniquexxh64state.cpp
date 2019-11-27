#include "uniquexxh64state.h"

namespace zeek {
void XXH64StateDeleter::operator()(XXH64_state_t *state) const {
  if (state == nullptr) {
    return;
  }

  XXH64_freeState(state);
}

UniqueXXH64State createXXH64State() {
  auto state = XXH64_createState();
  if (state == nullptr) {
    return nullptr;
  }

  static const XXH64_hash_t kXXH64Seed{0U};
  if (XXH64_reset(state, kXXH64Seed) == XXH_ERROR) {
    return nullptr;
  }

  return UniqueXXH64State(state);
}
} // namespace zeek
