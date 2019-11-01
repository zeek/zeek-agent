// This unit test is a variation of the `core` unit test that uses a
// `publisher` instead of an event-based `driver` actor.

#define SUITE publisher

#include "broker/publisher.hh"

#include "test.hh"

#include <caf/actor.hpp>
#include <caf/behavior.hpp>
#include <caf/downstream.hpp>
#include <caf/error.hpp>
#include <caf/exit_reason.hpp>
#include <caf/scoped_actor.hpp>
#include <caf/send.hpp>
#include <caf/stateful_actor.hpp>
#include <caf/stream.hpp>

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

using namespace broker;
using namespace broker::detail;

using namespace caf;

using stream_type = stream<data_message>;

namespace {

struct consumer_state {
  std::vector<data_message> xs;
};

behavior consumer(stateful_actor<consumer_state>* self,
                  filter_type ts, const actor& src) {
  self->send(self * src, atom::join::value, std::move(ts));
  return {
    [=](const stream_type& in) {
      self->make_sink(
        // Input stream.
        in,
        // Initialize state.
        [](unit_t&) {
          // nop
        },
        // Process single element.
        [=](unit_t&, data_message x) {
          self->state.xs.emplace_back(std::move(x));
        },
        // Cleanup.
        [](unit_t&, const caf::error&) {
          // nop
        }
      );
    },
    [=](atom::get) {
      return self->state.xs;
    }
  };
}

} // namespace <anonymous>

CAF_TEST_FIXTURE_SCOPE(publisher_tests, base_fixture)

CAF_TEST(blocking_publishers) {
  // Spawn/get/configure core actors.
  broker_options options;
  options.disable_ssl = true;
  auto core1 = ep.core();
  auto core2 = sys.spawn(core_actor, filter_type{"a"}, options, nullptr);
  anon_send(core1, atom::subscribe::value, filter_type{"a"});
  anon_send(core1, atom::no_events::value);
  anon_send(core2, atom::no_events::value);
  self->send(core1, atom::peer::value, core2);
  // Connect a consumer (leaf) to core2, which receives only a subset of 'a'.
  auto leaf = sys.spawn(consumer, filter_type{"a/b"}, core2);
  run();
  { // Lifetime scope of our publishers.
    // Spin up two publishers: one for "a" and one for "a/b".
    auto pub1 = ep.make_publisher("a");
    auto pub2 = ep.make_publisher("a/b");
    pub1.drop_all_on_destruction();
    pub2.drop_all_on_destruction();
    auto d1 = pub1.worker();
    auto d2 = pub2.worker();
    run();
    // Data flows from our publishers to core1 to core2 and finally to leaf.
    using buf = std::vector<data_message>;
    // First, set of published messages gets filtered out at core2.
    pub1.publish(0);
    run();
    // Second, set of published messages gets delivered to leaf.
    pub2.publish(true);
    run();
    // Third, set of published messages gets again filtered out at core2.
    pub1.publish({1, 2, 3});
    run();
    // Fourth, set of published messages gets delivered to leaf again.
    pub2.publish({false, true});
    run();
    // Check log of the consumer.
    self->send(leaf, atom::get::value);
    sched.prioritize(leaf);
    consume_message();
    self->receive(
      [](const buf& xs) {
        auto expected = data_msgs({{"a/b", true}, {"a/b", false},
                                   {"a/b", true}});
        CAF_REQUIRE_EQUAL(xs, expected);
      }
    );
  }
  // Shutdown.
  CAF_MESSAGE("Shutdown core actors.");
  anon_send_exit(core1, exit_reason::user_shutdown);
  anon_send_exit(core2, exit_reason::user_shutdown);
  anon_send_exit(leaf, exit_reason::user_shutdown);
}

CAF_TEST(nonblocking_publishers) {
  // Spawn/get/configure core actors.
  broker_options options;
  options.disable_ssl = true;
  auto core1 = ep.core();
  auto core2 = sys.spawn(core_actor, filter_type{"a", "b", "c"}, options, nullptr);
  anon_send(core1, atom::subscribe::value, filter_type{"a", "b", "c"});
  anon_send(core1, atom::no_events::value);
  anon_send(core2, atom::no_events::value);
  self->send(core1, atom::peer::value, core2);
  // Connect a consumer (leaf) to core2.
  auto leaf = sys.spawn(consumer, filter_type{"b"}, core2);
  run();
  // publish_all uses thread communication which would deadlock when using our
  // test_scheduler. We avoid this by pushing the call to publish_all to its
  // own thread.
  using buf_type = std::vector<data_message>;
  ep.publish_all_nosync(
    // Initialize send buffer with 10 elements.
    [](buf_type& xs) {
      xs = data_msgs({{"a", 0}, {"b", true}, {"a", 1}, {"a", 2},
                      {"b", false}, {"b", true}, {"a", 3},
                      {"b", false}, {"a", 4}, {"a", 5}});
    },
    // Get next element.
    [](buf_type& xs, downstream<data_message>& out, size_t num) {
      auto n = std::min(num, xs.size());
      for (size_t i = 0u; i < n; ++i)
        out.push(xs[i]);
      xs.erase(xs.begin(), xs.begin() + static_cast<ptrdiff_t>(n));
    },
    // Did we reach the end?.
    [](const buf_type& xs) {
      return xs.empty();
    }
  );
  // Communication is identical to the driver-driven test in test/cpp/core.cc
  run();
  // Check log of the consumer.
  self->send(leaf, atom::get::value);
  sched.prioritize(leaf);
  consume_message();
  self->receive(
    [](const buf_type& xs) {
      auto expected = data_msgs({{"b", true}, {"b", false},
                                 {"b", true}, {"b", false}});
      CAF_REQUIRE_EQUAL(xs, expected);
    }
  );
  // Shutdown.
  CAF_MESSAGE("Shutdown core actors.");
  anon_send_exit(core1, exit_reason::user_shutdown);
  anon_send_exit(core2, exit_reason::user_shutdown);
  anon_send_exit(leaf, exit_reason::user_shutdown);
}

CAF_TEST_FIXTURE_SCOPE_END()
