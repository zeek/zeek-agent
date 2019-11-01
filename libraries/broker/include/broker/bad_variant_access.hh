#pragma once

#include <exception>

namespace broker {

class bad_variant_access : public std::exception {
public:
  bad_variant_access() = default;

  const char* what() const noexcept override {
    return "bad variant access";
  }
};

} // namespace broker
