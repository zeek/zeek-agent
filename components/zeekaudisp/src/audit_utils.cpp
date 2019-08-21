#include "audit_utils.h"

#include <iostream>

namespace zeek {
bool convertHexDigitToByte(char &output, const char &input) {
  if (input >= '0' && input <= '9') {
    output = input - '0';

  } else if (input >= 'A' && input <= 'F') {
    output = 0x0A + (input - 'A');

  } else {
    return false;
  }

  return true;
}

bool convertHexString(std::string &output, const std::string &buffer) {
  if ((buffer.size() % 2U) != 0U) {
    output = {};
    return false;
  }

  std::size_t byte_size = buffer.size() / 2U;
  output.resize(byte_size);

  auto output_buffer = &output[0];
  auto input_buffer = buffer.data();

  for (auto i = 0U; i < byte_size; ++i) {
    auto &output_byte = output_buffer[i];

    auto input_buffer_base_index = i * 2U;
    if (!convertHexDigitToByte(output_byte,
                               input_buffer[input_buffer_base_index + 1U])) {
      output = {};
      return false;
    }

    char nibble{};
    if (!convertHexDigitToByte(nibble, input_buffer[input_buffer_base_index])) {
      output = {};
      return false;
    }

    output_byte |= (nibble << 4U);
  }

  return true;
}

bool convertAuditString(std::string &output, const std::string &buffer) {
  if (buffer.empty()) {
    output = {};
    return true;
  }

  if (buffer[0] == '"') {
    if (buffer.size() < 2U) {
      return false;
    }

    output.assign(buffer, 1U, buffer.size() - 2U);
    return true;

  } else {
    return convertHexString(output, buffer);
  }
}
} // namespace zeek
