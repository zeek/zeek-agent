#pragma once

#include <caf/logger.hpp>

#define BROKER_LOG(level, ...) CAF_LOG_IMPL("broker", level, __VA_ARGS__)

#define BROKER_TRACE(...)                                                      \
  BROKER_LOG(CAF_LOG_LEVEL_TRACE, "ENTRY" << __VA_ARGS__);                     \
  auto CAF_UNIFYN(broker_log_trace_guard_) = ::caf::detail::make_scope_guard(  \
    [=] { BROKER_LOG(CAF_LOG_LEVEL_TRACE, "EXIT"); })

#define BROKER_DEBUG(...) BROKER_LOG(CAF_LOG_LEVEL_DEBUG, __VA_ARGS__)

#define BROKER_INFO(...) BROKER_LOG(CAF_LOG_LEVEL_INFO, __VA_ARGS__)

#define BROKER_WARNING(...) BROKER_LOG(CAF_LOG_LEVEL_WARNING, __VA_ARGS__)

#define BROKER_ERROR(...) BROKER_LOG(CAF_LOG_LEVEL_ERROR, __VA_ARGS__)

#define BROKER_ARG CAF_ARG

#define BROKER_ARG2 CAF_ARG2

#define BROKER_ARG3 CAF_ARG3
