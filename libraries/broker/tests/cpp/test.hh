#pragma once

#ifdef SUITE
#define CAF_SUITE SUITE
#endif

#include <caf/test/unit_test.hpp>

#include <caf/actor_system.hpp>
#include <caf/scheduler/test_coordinator.hpp>
#include <caf/scoped_actor.hpp>

#include <caf/io/network/test_multiplexer.hpp>

#include "broker/configuration.hh"
#include "broker/endpoint.hh"

// -- test setup macros --------------------------------------------------------

#define TEST CAF_TEST
#define FIXTURE_SCOPE CAF_TEST_FIXTURE_SCOPE
#define FIXTURE_SCOPE_END CAF_TEST_FIXTURE_SCOPE_END

// -- logging macros -----------------------------------------------------------

#define ERROR CAF_TEST_PRINT_ERROR
#define INFO CAF_TEST_PRINT_INFO
#define VERBOSE CAF_TEST_PRINT_VERBOSE
#define MESSAGE CAF_MESSAGE

// -- macros for checking results ---------------------------------------------

#define REQUIRE CAF_REQUIRE
#define REQUIRE_EQUAL CAF_REQUIRE_EQUAL
#define REQUIRE_NOT_EQUAL CAF_REQUIRE_NOT_EQUAL
#define REQUIRE_LESS CAF_REQUIRE_LESS
#define REQUIRE_LESS_EQUAL CAF_REQUIRE_LESS_EQUAL
#define REQUIRE_GREATER CAF_REQUIRE_GREATER
#define REQUIRE_GREATER_EQUAL CAF_REQUIRE_GREATER_EQUAL
#define CHECK CAF_CHECK
#define CHECK_EQUAL CAF_CHECK_EQUAL
#define CHECK_NOT_EQUAL CAF_CHECK_NOT_EQUAL
#define CHECK_LESS CAF_CHECK_LESS
#define CHECK_LESS_EQUAL CAF_CHECK_LESS_EQUAL
#define CHECK_GREATER CAF_CHECK_GREATER
#define CHECK_GREATER_EQUAL CAF_CHECK_GREATER_EQUAL
#define CHECK_FAIL CAF_CHECK_FAIL
#define FAIL CAF_FAIL

// -- fixtures -----------------------------------------------------------------

/// A fixture that offes a `context` configured with `test_coordinator` as
/// scheduler as well as a `scoped_actor`.
class base_fixture {
public:
  using scheduler_type = caf::scheduler::test_coordinator;

  base_fixture();

  virtual ~base_fixture();

  broker::endpoint ep;
  caf::actor_system& sys;
  caf::scoped_actor self;
  scheduler_type& sched;
  caf::timespan credit_round_interval;

  void run();

  void consume_message();

private:
  static broker::configuration make_config();
};

inline broker::data value_of(caf::expected<broker::data> x) {
  if (!x) {
    FAIL("cannot unbox expected<data>: " << to_string(x.error()));
  }
  return std::move(*x);
}

inline caf::error error_of(caf::expected<broker::data> x) {
  if (x) {
    FAIL("cannot get error of expected<data>, contains value: "
         << to_string(*x));
  }
  return std::move(x.error());
}

/// Convenience function for creating a vector of events from topic and data
/// pairs.
inline std::vector<broker::data_message>
data_msgs(std::initializer_list<std::pair<broker::topic, broker::data>> xs) {
  std::vector<broker::data_message> result;
  for (auto& x : xs)
    result.emplace_back(x.first, x.second);
  return result;
}
