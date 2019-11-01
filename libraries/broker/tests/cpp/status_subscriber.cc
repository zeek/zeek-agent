#define SUITE status_subscriber

#include "broker/status_subscriber.hh"

#include "test.hh"

#include <iostream>
#include <string>
#include <utility>

#include <caf/exit_reason.hpp>
#include <caf/group.hpp>
#include <caf/send.hpp>

#include "broker/atoms.hh"
#include "broker/endpoint.hh"
#include "broker/error.hh"
#include "broker/status.hh"

using std::cout;
using std::endl;
using std::string;

using namespace caf;
using namespace broker;
using namespace broker::detail;

namespace {

struct fixture : base_fixture {
  fixture() {
    errors = sys.groups().get_local("broker/errors");
    statuses = sys.groups().get_local("broker/statuses");
  }

  void push(::broker::error x) {
    anon_send(errors, atom::local::value, std::move(x));
  }

  void push(status x) {
    anon_send(statuses, atom::local::value, std::move(x));
  }

  group errors;
  group statuses;
};

} // namespace <anonymous>

CAF_TEST_FIXTURE_SCOPE(status_subscriber_tests, fixture)

CAF_TEST(base_tests) {
  auto sub1 = ep.make_status_subscriber(true);
  auto sub2 = ep.make_status_subscriber(false);
  run();
  CAF_REQUIRE_EQUAL(sub1.available(), 0u);
  CAF_REQUIRE_EQUAL(sub2.available(), 0u);
  CAF_MESSAGE("test error event");
  ::broker::error e1 = ec::type_clash;
  push(e1);
  run();
  CAF_REQUIRE_EQUAL(sub1.available(), 1u);
  CAF_REQUIRE_EQUAL(sub1.get(), e1);
  CAF_REQUIRE_EQUAL(sub2.available(), 1u);
  CAF_REQUIRE_EQUAL(sub2.get(), e1);
  CAF_MESSAGE("test status event");
  auto s1 = status::make<sc::unspecified>("foobar");;
  push(s1);
  run();
  CAF_REQUIRE_EQUAL(sub1.available(), 1u);
  CAF_REQUIRE_EQUAL(sub1.get(), s1);
  CAF_REQUIRE_EQUAL(sub2.available(), 0u);
  CAF_MESSAGE("shutdown");
  anon_send_exit(ep.core(), exit_reason::user_shutdown);
}

CAF_TEST_FIXTURE_SCOPE_END()
