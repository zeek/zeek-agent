#pragma once

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <caf/binary_serializer.hpp>
#include <caf/fwd.hpp>
#include <caf/variant.hpp>

#include "broker/fwd.hh"

namespace broker {
namespace detail {

class generator_file_writer {
public:
  struct format {
    static constexpr uint32_t magic = 0x2EECC0DE;

    static constexpr uint8_t version = 1;

    static constexpr size_t header_size = sizeof(magic) + sizeof(version);

    enum class entry_type : uint8_t {
      new_topic,
      data_message,
      command_message,
    };
  };

  using data_or_command_message = caf::variant<data_message, command_message>;

  generator_file_writer();

  generator_file_writer(generator_file_writer&&) = delete;

  generator_file_writer(const generator_file_writer&) = delete;

  generator_file_writer& operator=(generator_file_writer&&) = delete;

  generator_file_writer& operator=(const generator_file_writer&) = delete;

  ~generator_file_writer();

  caf::error open(std::string file_name);

  caf::error write(const data_message& x);

  caf::error write(const command_message& x);

  caf::error write(const data_or_command_message& x);

  caf::error flush();

  size_t flush_threshold() const noexcept {
    return flush_threshold_;
  }

  void flush_threshold(size_t x) noexcept {
    flush_threshold_ = x;
  }

  bool operator!() const;

  explicit operator bool() const;

private:
  caf::error topic_id(const topic& x, uint16_t& id);

  std::vector<char> buf_;
  caf::binary_serializer sink_;
  std::ofstream f_;
  size_t flush_threshold_;
  std::vector<topic> topic_table_;
  std::string file_name_;
};

using generator_file_writer_ptr = std::unique_ptr<generator_file_writer>;

generator_file_writer_ptr make_generator_file_writer(const std::string& fname);

generator_file_writer& operator<<(generator_file_writer& out,
                                  const data_message& x);

} // namespace detail
} // namespace broker
