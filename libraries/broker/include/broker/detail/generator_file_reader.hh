#pragma once

#include <memory>
#include <cstddef>

#include <caf/binary_deserializer.hpp>

#include "broker/detail/data_generator.hh"
#include "broker/fwd.hh"
#include "broker/topic.hh"

namespace broker {
namespace detail {

class generator_file_reader {
public:
  using value_type = caf::variant<data_message, command_message>;

  generator_file_reader(int fd, void* addr, size_t file_size);

  generator_file_reader(generator_file_reader&&) = delete;

  generator_file_reader(const generator_file_reader&) = delete;

  generator_file_reader& operator=(generator_file_reader&&) = delete;

  generator_file_reader& operator=(const generator_file_reader&) = delete;

  ~generator_file_reader();

  bool at_end() const;

  void rewind();

  caf::error read(value_type& x);

private:
  int fd_;
  void* addr_;
  size_t file_size_;
  caf::binary_deserializer source_;
  data_generator generator_;
  std::vector<topic> topic_table_;
};

using generator_file_reader_ptr = std::unique_ptr<generator_file_reader>;

generator_file_reader_ptr make_generator_file_reader(const std::string& fname);

} // namespace detail
} // namespace broker
