#pragma once

#include <string>
#include <unordered_map>

#include "broker/data.hh"

namespace broker {

using backend_options = std::unordered_map<std::string, data>;

} // namespace broker
