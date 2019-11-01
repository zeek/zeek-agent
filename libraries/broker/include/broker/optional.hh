#pragma once

#include <caf/optional.hpp>

#include "broker/none.hh"

namespace broker {

using caf::optional;

} // namespace broker

namespace std {

template <class T>
struct hash<broker::optional<T>> {
  using result_type = typename hash<T>::result_type;
  using argument_type = broker::optional<T>;

  inline result_type operator()(const argument_type& arg) const {
    if (arg)
      return std::hash<T>{}(*arg);
    return result_type{};
  }
};

} // namespace std
