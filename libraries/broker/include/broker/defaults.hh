#pragma once

#include "caf/string_view.hpp"

// This header contains hard-coded default values for various Broker options.

namespace broker {
namespace defaults {

extern const caf::string_view output_generator_file;

extern const size_t output_generator_file_cap;

} // namespace defaults
} // namespace broker
