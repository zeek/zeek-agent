#define SUITE topic

#include "broker/topic.hh"

#include "test.hh"

using namespace broker;

namespace {

auto sep = std::string{topic::sep};

} // namespace <anonymous>

TEST(cleaning) {
  auto sep3 = sep + sep + sep;
  CHECK_EQUAL(topic{sep3}, ""_t);
  auto t = topic{"foo" + sep3};
  CHECK_EQUAL(t, "foo");
  t = sep3 + "foo";
  CHECK_EQUAL(t, sep + "foo");
  t = sep3 + "foo" + sep3;
  CHECK_EQUAL(t, sep + "foo");
}

TEST(concatenation) {
  topic t;
  t /= "foo";
  CHECK_EQUAL(t, "foo");
  t /= "bar";
  CHECK_EQUAL(t, "foo" + sep + "bar");
  t /= "/baz";
  CHECK_EQUAL(t, "foo" + sep + "bar" + sep + "baz");
}

TEST(split) {
  auto xs = topic::split("foo/bar/baz"_t);
  REQUIRE_EQUAL(xs.size(), 3u);
  CHECK_EQUAL(xs[0], "foo");
  CHECK_EQUAL(xs[1], "bar");
  CHECK_EQUAL(xs[2], "baz");
  auto framed = topic::split("/foo/bar/baz/"_t);
  CHECK(xs == framed);
}

TEST(join) {
  std::vector<std::string> xs{"/foo", "bar/", "/baz"};
  auto t = topic::join(xs);
  CHECK_EQUAL(t, sep + "foo" + sep + "bar" + sep + "baz");
}

TEST(prefix) {
  topic t0 = "/zeek/";
  topic t1 = "/zeek/events/";
  topic t2 = "/zeek/events/debugging/";
  topic t3 = "/zeek/stores/";
  topic t4 = "/zeek/stores/masters/";
  topic t5 = "/";
  // t0 is a prefix of all topics except t5
  CAF_CHECK( t0.prefix_of(t0));
  CAF_CHECK( t0.prefix_of(t1));
  CAF_CHECK( t0.prefix_of(t2));
  CAF_CHECK( t0.prefix_of(t3));
  CAF_CHECK( t0.prefix_of(t4));
  CAF_CHECK(!t0.prefix_of(t5));
  // t1 is a prefix of itself and t2
  CAF_CHECK(!t1.prefix_of(t0));
  CAF_CHECK( t1.prefix_of(t1));
  CAF_CHECK( t1.prefix_of(t2));
  CAF_CHECK(!t1.prefix_of(t3));
  CAF_CHECK(!t1.prefix_of(t4));
  CAF_CHECK(!t1.prefix_of(t5));
  // t2 is only a prefix of itself
  CAF_CHECK(!t2.prefix_of(t0));
  CAF_CHECK(!t2.prefix_of(t1));
  CAF_CHECK( t2.prefix_of(t2));
  CAF_CHECK(!t2.prefix_of(t3));
  CAF_CHECK(!t2.prefix_of(t4));
  CAF_CHECK(!t2.prefix_of(t5));
  // t3 is a prefix of itself and t4
  CAF_CHECK(!t3.prefix_of(t0));
  CAF_CHECK(!t3.prefix_of(t1));
  CAF_CHECK(!t3.prefix_of(t2));
  CAF_CHECK( t3.prefix_of(t3));
  CAF_CHECK( t3.prefix_of(t4));
  CAF_CHECK(!t3.prefix_of(t5));
  // t4 is only a prefix of itself
  CAF_CHECK(!t4.prefix_of(t0));
  CAF_CHECK(!t4.prefix_of(t1));
  CAF_CHECK(!t4.prefix_of(t2));
  CAF_CHECK(!t4.prefix_of(t3));
  CAF_CHECK( t4.prefix_of(t4));
  CAF_CHECK(!t4.prefix_of(t5));
  // t5 is a prefix of all topics
  CAF_CHECK( t5.prefix_of(t0));
  CAF_CHECK( t5.prefix_of(t1));
  CAF_CHECK( t5.prefix_of(t2));
  CAF_CHECK( t5.prefix_of(t3));
  CAF_CHECK( t5.prefix_of(t4));
  CAF_CHECK( t5.prefix_of(t5));
}
