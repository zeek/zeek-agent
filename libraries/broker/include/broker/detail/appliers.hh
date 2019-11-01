#pragma once

#include "broker/data.hh"
#include "broker/error.hh"
#include "broker/expected.hh"
#include "broker/status.hh"
#include "broker/time.hh"

#include "broker/detail/type_traits.hh"

namespace broker {
namespace detail {

template <class T>
constexpr bool is_additive_group() {
  return std::is_same<T, count>::value
    || std::is_same<T, integer>::value
    || std::is_same<T, real>::value
    || std::is_same<T, timespan>::value;
}

struct adder {
  using result_type = expected<void>;

  template <class T>
  auto operator()(T&) -> disable_if_t<is_additive_group<T>(), result_type> {
    return ec::type_clash;
  }

  template <class T>
  auto operator()(T& c) -> enable_if_t<is_additive_group<T>(), result_type> {
    auto x = caf::get_if<T>(&value);
    if (!x)
      return ec::type_clash;
    c += *x;
    return {};
  }

  result_type operator()(timestamp& tp) {
    auto s = caf::get_if<timespan>(&value);
    if (!s)
      return ec::type_clash;
    tp += *s;
    return {};
  }

  result_type operator()(std::string& str) {
    auto x = caf::get_if<std::string>(&value);
    if (!x)
      return ec::type_clash;
    str += *x;
    return {};
  }

  result_type operator()(vector& v) {
    v.push_back(value);
    return {};
  }

  result_type operator()(set& s) {
    s.insert(value);
    return {};
  }

  result_type operator()(table& t) {
    // Data must come as key-value pair to be valid, which we model as
    // vector of length 2.
    auto v = caf::get_if<vector>(&value);
    if (!v)
      return ec::type_clash;
    if (v->size() != 2)
      return ec::invalid_data;
    t[v->front()] = v->back();
    return {};
  }

  const data& value;
};

struct remover {
  using result_type = expected<void>;

  template <class T>
  auto operator()(T&) -> disable_if_t<is_additive_group<T>(), result_type> {
    return ec::type_clash;
  }

  template <class T>
  auto operator()(T& c) -> enable_if_t<is_additive_group<T>(), result_type> {
    auto x = caf::get_if<T>(&value);
    if (!x)
      return ec::type_clash;
    c -= *x;
    return {};
  }

  result_type operator()(timestamp& ts) {
    auto s = caf::get_if<timespan>(&value);
    if (!s)
      return ec::type_clash;
    ts -= *s;
    return {};
  }

  result_type operator()(vector& v) {
    if (!v.empty())
      v.pop_back();
    return {};
  }

  result_type operator()(set& s) {
    s.erase(value);
    return {};
  }

  result_type operator()(table& t) {
    t.erase(value);
    return {};
  }

  const data& value;
};

struct retriever {
  using result_type = expected<data>;

  template <class T>
  result_type operator()(const T& x) const {
    return x;
  }

  result_type operator()(const vector& v) const {
    count i;
    auto x = caf::get_if<count>(&aspect);
    if (x)
      i = *x;
    else {
      auto y = caf::get_if<integer>(&aspect);
      if (!y || *y < 0)
        return ec::type_clash;
      i = static_cast<count>(*y);
    }
    if (i >= v.size())
      return ec::no_such_key;
    return v[i];
  }

  result_type operator()(const set& s) const {
    return s.count(aspect) == 1;
  }

  result_type operator()(const table& t) const {
    auto i = t.find(aspect);
    if (i == t.end())
      return ec::no_such_key;
    return i->second;
  }

  const data& aspect;
};

} // namespace detail
} // namespace broker
