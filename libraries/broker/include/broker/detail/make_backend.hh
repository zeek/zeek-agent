#pragma once

#include <memory>

#include "broker/backend.hh"
#include "broker/backend_options.hh"

#include "broker/detail/abstract_backend.hh"

namespace broker {
namespace detail {

std::unique_ptr<abstract_backend> make_backend(backend type,
                                               backend_options opts);

} // namespace detail
} // namespace broker
