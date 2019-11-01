#define SUITE data

#include "broker/data.hh"

#include "test.hh"

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <type_traits>
#include <utility>

#include "broker/convert.hh"
#include "broker/optional.hh"

using namespace broker;

TEST(basic) {
  CHECK(std::is_same<boolean, bool>::value);
  CHECK(std::is_same<integer, int64_t>::value);
  CHECK(std::is_same<count, uint64_t>::value);
  CHECK(std::is_same<real, double>::value);
}

TEST(timespan) {
  auto s = timespan{42};
  CHECK(std::chrono::nanoseconds{42} == s);
}

TEST(timestamp) {
  auto ts = timestamp{timespan{42}};
  CHECK(ts.time_since_epoch() == timespan{42});
}

TEST(enum) {
  auto e = enum_value{"foo"};
  CHECK_EQUAL(e.name, "foo");
}

TEST(address) {
  address a;
  // Default-constructed addresses are considered IPv6.
  CHECK(!a.is_v4());
  CHECK(a.is_v6());
  MESSAGE("parsing");
  auto opt = to<address>("dead::beef");
  REQUIRE(opt);
  CHECK(!opt->is_v4());
  CHECK(opt->is_v6());
  opt = to<address>("1.2.3.4");
  REQUIRE(opt);
  CHECK(opt->is_v4());
  CHECK(!opt->is_v6());
  MESSAGE("printing");
  CHECK_EQUAL(to_string(*opt), "1.2.3.4");
  MESSAGE("masking");
  CHECK(opt->mask(96 + 16));
  CHECK_EQUAL(to_string(*opt), "1.2.0.0");
}

TEST(port) {
  port p;
  CHECK_EQUAL(p.number(), 0u);
  CHECK(p.type() == port::protocol::unknown);
  p = {80, port::protocol::tcp};
  MESSAGE("parsing");
  auto opt = to<port>("8/icmp");
  REQUIRE(opt);
  CHECK_EQUAL(*opt, port(8, port::protocol::icmp));
  opt = to<port>("42/nonsense");
  REQUIRE(opt);
  CHECK_EQUAL(*opt, port(42, port::protocol::unknown));
  MESSAGE("printing");
  CHECK_EQUAL(to_string(p), "80/tcp");
  p = {0, port::protocol::unknown};
  CHECK_EQUAL(to_string(p), "0/?");
}

TEST(subnet) {
  subnet sn;
  CHECK_EQUAL(sn.length(), 0u);
  CHECK_EQUAL(to_string(sn), "::/0");
  auto a = to<address>("1.2.3.4");
  auto b = to<address>("1.2.3.0");
  REQUIRE(a);
  REQUIRE(b);
  sn = {*a, 24};
  CHECK_EQUAL(sn.length(), 24u);
  CHECK_EQUAL(sn.network(), *b);
}

TEST(data - construction) {
  MESSAGE("default construction");
  data d;
  CHECK(caf::get_if<none>(&d));
}

TEST(data - assignment) {
  data d;
  d = 42;
  auto i = caf::get_if<integer>(&d);
  REQUIRE(i);
  CHECK_EQUAL(*i, 42);
  d = data{7};
  i = caf::get_if<integer>(&d);
  CHECK_EQUAL(*i, 7);
  d = "foo";
  auto s = caf::get_if<std::string>(&d);
  REQUIRE(s);
  CHECK_EQUAL(*s, "foo");
}

TEST(data - relational operators) {
  CHECK_NOT_EQUAL(data{true}, data{false});
  CHECK_NOT_EQUAL(data{1}, data{true});
  CHECK_NOT_EQUAL(data{-1}, data{1});
  CHECK_NOT_EQUAL(data{1}, data{1u});
  CHECK_NOT_EQUAL(data{1.111}, data{1.11});
  CHECK_EQUAL(data{1.111}, data{1.111});
}

TEST(data - vector) {
  vector v{42, 43, 44};
  REQUIRE_EQUAL(v.size(), 3u);
  CHECK_EQUAL(v[1], data{43});
  CHECK_EQUAL(to_string(v), "(42, 43, 44)");
}

TEST(data - set) {
  set s{"foo", "bar", "baz", "foo"};
  CHECK_EQUAL(s.size(), 3u); // one duplicate
  CHECK(s.find("bar") != s.end());
  CHECK(s.find("qux") == s.end());
  CHECK_EQUAL(to_string(s), "{bar, baz, foo}");
}

TEST(data - table) {
  table t{{"foo", 42}, {"bar", 43}, {"baz", 44}};
  auto i = t.find("foo");
  REQUIRE(i != t.end());
  CHECK_EQUAL(i->second, data{42});
  CHECK_EQUAL(to_string(t), "{bar -> 43, baz -> 44, foo -> 42}");
}
