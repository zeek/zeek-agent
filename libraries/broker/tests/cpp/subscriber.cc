// This unit test is a variation of the `core` unit test that uses a
// `subscriber` instead of an event-based `consumer` actor.

#define SUITE subscriber

#include "broker/subscriber.hh"

#include "test.hh"

#include <caf/actor.hpp>
#include <caf/downstream.hpp>
#include <caf/event_based_actor.hpp>
#include <caf/exit_reason.hpp>
#include <caf/send.hpp>

#include "broker/atoms.hh"
#include "broker/configuration.hh"
#include "broker/convert.hh"
#include "broker/core_actor.hh"
#include "broker/data.hh"
#include "broker/endpoint.hh"
#include "broker/filter_type.hh"
#include "broker/message.hh"
#include "broker/topic.hh"

using std::cout;
using std::endl;
using std::string;

using namespace caf;
using namespace broker;
using namespace broker::detail;

namespace {

void driver(event_based_actor* self, const actor& sink) {
  using buf_type = std::vector<data_message>;
  self->make_source(
    // Destination.
    sink,
    // Initialize send buffer with 10 elements.
    [](buf_type& xs) {
      xs = data_msgs({{"a", 0},     {"b", true}, {"a", 1}, {"a", 2},
                      {"b", false}, {"b", true}, {"a", 3}, {"b", false},
                      {"a", 4},     {"a", 5}});
    },
    // Get next element.
    [](buf_type& xs, downstream<data_message>& out, size_t num) {
      auto n = std::min(num, xs.size());
      for (size_t i = 0u; i < n; ++i)
        out.push(xs[i]);
      xs.erase(xs.begin(), xs.begin() + static_cast<ptrdiff_t>(n));
    },
    // Did we reach the end?.
    [](const buf_type& xs) { return xs.empty(); });
}

} // namespace <anonymous>

CAF_TEST_FIXTURE_SCOPE(subscriber_tests, base_fixture)

CAF_TEST(blocking_subscriber) {
  // Spawn/get/configure core actors.
  broker_options options;
  options.disable_ssl = true;
  auto core1 = sys.spawn(core_actor, filter_type{"a", "b", "c"}, options, nullptr);
  auto core2 = ep.core();
  anon_send(core2, atom::subscribe::value, filter_type{"a", "b", "c"});
  anon_send(core1, atom::no_events::value);
  anon_send(core2, atom::no_events::value);
  run();
  // Connect a consumer (leaf) to core2.
  // auto leaf = sys.spawn(consumer, filter_type{"b"}, core2);
  auto sub = ep.make_subscriber(filter_type{"b"});
  sub.set_rate_calculation(false);
  auto leaf = sub.worker();
  CAF_MESSAGE("core1: " << to_string(core1));
  CAF_MESSAGE("core2: " << to_string(core2));
  CAF_MESSAGE("leaf: " << to_string(leaf));
  // Initiate handshake between core1 and core2.
  self->send(core1, atom::peer::value, core2);
  run();
  // Spin up driver on core1.
  auto d1 = sys.spawn(driver, core1);
  CAF_MESSAGE("driver: " << to_string(d1));
  run();
  CAF_MESSAGE("check content of the subscriber's buffer");
  using buf = std::vector<data_message>;
  auto expected = data_msgs({{"b", true}, {"b", false},
                             {"b", true}, {"b", false}});
  CAF_CHECK_EQUAL(sub.poll(), expected);
  // Shutdown.
  CAF_MESSAGE("Shutdown core actors.");
  anon_send_exit(core1, exit_reason::user_shutdown);
  anon_send_exit(core2, exit_reason::user_shutdown);
  anon_send_exit(leaf, exit_reason::user_shutdown);
  anon_send_exit(d1, exit_reason::user_shutdown);
}

CAF_TEST(nonblocking_subscriber) {
  // Spawn/get/configure core actors.
  broker_options options;
  options.disable_ssl = true;
  auto core1 = sys.spawn(core_actor, filter_type{"a", "b", "c"}, options, nullptr);
  auto core2 = ep.core();
  anon_send(core1, atom::no_events::value);
  anon_send(core2, atom::no_events::value);
  anon_send(core2, atom::subscribe::value, filter_type{"a", "b", "c"});
  self->send(core1, atom::peer::value, core2);
  run();
  // Connect a subscriber (leaf) to core2.
  using buf = std::vector<data_message>;
  buf result;
  ep.subscribe_nosync(
    {"b"},
    [](unit_t&) {
      // nop
    },
    [&](unit_t&, data_message x) {
      result.emplace_back(std::move(x));
    },
    [](unit_t&, const error&) {
      // nop
    }
  );
  // Spin up driver on core1.
  auto d1 = sys.spawn(driver, core1);
  // Communication is identical to the consumer-centric test in test/cpp/core.cc
  run();
  auto expected = data_msgs({{"b", true}, {"b", false},
                             {"b", true}, {"b", false}});
  CAF_REQUIRE_EQUAL(result, expected);
  // Shutdown.
  CAF_MESSAGE("Shutdown core actors.");
  anon_send_exit(core1, exit_reason::user_shutdown);
  anon_send_exit(core2, exit_reason::user_shutdown);
}

CAF_TEST_FIXTURE_SCOPE_END()
