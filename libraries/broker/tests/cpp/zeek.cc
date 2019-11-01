// We leave testing the actual communication with Zeek to Python tests. Here we
// just check that the messages are constructed and parsed correctly.

#define SUITE zeek

#include "broker/zeek.hh"

#include "test.hh"

#include <utility>

#include "broker/data.hh"

using namespace broker;

TEST(event) {
  auto args = vector{1, "s", port(42, port::protocol::tcp)};
  zeek::Event ev("test", vector(args));
  zeek::Event ev2(std::move(ev));
  CHECK_EQUAL(ev2.name(), "test");
  CHECK_EQUAL(ev2.args(), args);
}
