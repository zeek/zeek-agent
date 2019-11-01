#pragma once

#include <string>
#include <vector>

#include <caf/stream_deserializer.hpp>
#include <caf/stream_serializer.hpp>

namespace broker {
namespace detail {

template <class T, class... Ts>
std::string to_blob(T&& x, Ts&&... xs) {
  std::string buf;
  caf::containerbuf<std::string> sb{buf};
  caf::stream_serializer<caf::containerbuf<std::string>&> serializer{sb};
  serializer(std::forward<T>(x), std::forward<Ts>(xs)...);
  return buf;
}

template <class T>
T from_blob(const void* buf, size_t size) {
  auto data = reinterpret_cast<char*>(const_cast<void*>(buf));
  caf::arraybuf<char> sb{data, size};
  caf::stream_deserializer<caf::arraybuf<char>&> deserializer{sb};
  T result;
  deserializer(result);
  return result;
}

template <class T>
T from_blob(const std::string& str) {
  return from_blob<T>(str.data(), str.size());
}

} // namespace detail
} // namespace broker
