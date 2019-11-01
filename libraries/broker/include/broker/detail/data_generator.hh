#pragma once

#include <random>
#include <unordered_map>

#include <caf/error.hpp>
#include <caf/fwd.hpp>

#include "broker/data.hh"
#include "broker/internal_command.hh"

namespace broker {
namespace detail {

/// Generates random Broker ::data from recorded meta data.
class data_generator {
public:
  /// Helper class for filling values with random content.
  struct mixer {
    data_generator& generator;

    template <class T>
    void operator()(T& x) {
      generator.shuffle(x);
    }
  };

  data_generator(caf::binary_deserializer& meta_data_source, size_t seed = 0);

  caf::error operator()(data& x);

  caf::error operator()(internal_command& x);

  caf::error generate(data& x);

  caf::error generate(data::type tag, data& x);

  caf::error generate(internal_command& x);

  caf::error generate(internal_command::type tag, internal_command& x);

  caf::error generate(vector& xs);

  caf::error generate(set& xs);

  caf::error generate(table& xs);

  caf::error generate(std::unordered_map<data, data>& xs);

  template <class T>
  caf::error generate(T& x) {
    shuffle(x);
    return caf::none;
  }

  caf::error generate(std::string& x);

  caf::error generate(enum_value& x);

  void shuffle(none&);

  void shuffle(boolean& x);

  template <class T>
  typename std::enable_if<std::is_arithmetic<T>::value>::type shuffle(T& x) {
    x = engine_();
  }

  void shuffle(std::string& x);

  void shuffle(enum_value& x);

  void shuffle(port& x);

  void shuffle(address& x);

  void shuffle(subnet& x);

  void shuffle(timespan& x);

  void shuffle(timestamp& x);

  void shuffle(data& x);

  void shuffle(vector& xs);

  void shuffle(set&);

  void shuffle(table& xs);

private:
  caf::binary_deserializer& source_;
  std::minstd_rand engine_;
  std::uniform_int_distribution<char> char_generator_;
  std::uniform_int_distribution<uint8_t> byte_generator_;
};

} // namespace detail
} // namespace broker
