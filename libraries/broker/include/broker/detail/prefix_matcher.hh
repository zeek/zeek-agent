#pragma once

#include <utility>
#include <vector>

#include <caf/cow_tuple.hpp>
#include <caf/message.hpp>

#include "broker/topic.hh"

namespace broker {
namespace detail {

struct prefix_matcher {
  using filter_type = std::vector<topic>;

  bool operator()(const filter_type& filter, const topic& t) const;

  template <class T>
  bool operator()(const filter_type& filter, const T& x) const {
    return (*this)(filter, get_topic(x));
  }
};


} // namespace detail
} // namespace broker
