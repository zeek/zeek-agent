#define SUITE meta_data_writer

#include "broker/detail/meta_data_writer.hh"

#include "test.hh"

#include <vector>

#include <caf/binary_deserializer.hpp>
#include <caf/binary_serializer.hpp>

using namespace broker;

namespace {

struct fixture {
  std::vector<char> buf;
  caf::binary_serializer sink;
  size_t read_pos;

  fixture() : sink(nullptr, buf), read_pos(0) {
    // nop
  }

  template <class T>
  void push(const T& x) {
    detail::meta_data_writer writer{sink};
    CHECK_EQUAL(writer(x), caf::none);
  }

  template <class T>
  T pull() {
    caf::binary_deserializer source{nullptr, buf.data() + read_pos,
                                    buf.size() - read_pos};
    T result;
    CHECK_EQUAL(source(result), caf::none);
    read_pos = buf.size() - source.remaining();
    return result;
  }

  bool at_end() const {
    return read_pos == buf.size();
  }
};

} // namespace

CAF_TEST_FIXTURE_SCOPE(meta_data_writer_tests, fixture)

CAF_TEST(default constructed data) {
  push(data{});
  CHECK_EQUAL(pull<data::type>(), data::type::none);
  CHECK(at_end());
}

CAF_TEST(boolean data) {
  push(data{true});
  CHECK_EQUAL(pull<data::type>(), data::type::boolean);
  CHECK(at_end());
}

CAF_TEST(count data) {
  push(data{count{42}});
  CHECK_EQUAL(pull<data::type>(), data::type::count);
  CHECK(at_end());
}

CAF_TEST(integer data) {
  push(data{integer{42}});
  CHECK_EQUAL(pull<data::type>(), data::type::integer);
  CHECK(at_end());
}

CAF_TEST(real data) {
  push(data{4.2});
  CHECK_EQUAL(pull<data::type>(), data::type::real);
  CHECK(at_end());
}

CAF_TEST(string data) {
  push(data{"hello world"});
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 11u);
  CHECK(at_end());
}

CAF_TEST(address data) {
  push(data{address{}});
  CHECK_EQUAL(pull<data::type>(), data::type::address);
  CHECK(at_end());
}

CAF_TEST(subnet data) {
  push(data{subnet{address{}, 24}});
  CHECK_EQUAL(pull<data::type>(), data::type::subnet);
  CHECK(at_end());
}

CAF_TEST(port data) {
  push(data{port{8080, port::protocol::tcp}});
  CHECK_EQUAL(pull<data::type>(), data::type::port);
  CHECK(at_end());
}

CAF_TEST(timestamp data) {
  push(data{timestamp{}});
  CHECK_EQUAL(pull<data::type>(), data::type::timestamp);
  CHECK(at_end());
}

CAF_TEST(timespan data) {
  push(data{timespan{}});
  CHECK_EQUAL(pull<data::type>(), data::type::timespan);
  CHECK(at_end());
}

CAF_TEST(enum_value data) {
  push(data{enum_value{"foobar"}});
  CHECK_EQUAL(pull<data::type>(), data::type::enum_value);
  CHECK_EQUAL(pull<uint32_t>(), 6u);
  CHECK(at_end());
}

CAF_TEST(set data) {
  set xs;
  xs.emplace(integer{1});
  xs.emplace(integer{2});
  xs.emplace(integer{3});
  push(data{xs});
  CHECK_EQUAL(pull<data::type>(), data::type::set);
  CHECK_EQUAL(pull<uint32_t>(), 3u);
  CHECK_EQUAL(pull<data::type>(), data::type::integer);
  CHECK_EQUAL(pull<data::type>(), data::type::integer);
  CHECK_EQUAL(pull<data::type>(), data::type::integer);
  CHECK(at_end());
}

CAF_TEST(table data) {
  table xs;
  xs.emplace(integer{1}, 2.);
  xs.emplace(integer{2}, "hello world");
  xs.emplace(integer{3}, address{});
  push(data{xs});
  CHECK_EQUAL(pull<data::type>(), data::type::table);
  CHECK_EQUAL(pull<uint32_t>(), 3u);
  CHECK_EQUAL(pull<data::type>(), data::type::integer);
  CHECK_EQUAL(pull<data::type>(), data::type::real);
  CHECK_EQUAL(pull<data::type>(), data::type::integer);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 11u);
  CHECK_EQUAL(pull<data::type>(), data::type::integer);
  CHECK_EQUAL(pull<data::type>(), data::type::address);
  CHECK(at_end());
}

CAF_TEST(vector data) {
  vector xs;
  xs.emplace_back(integer{42});
  xs.emplace_back(std::string{"hello world"});
  xs.emplace_back(12.34);
  push(data{xs});
  CHECK_EQUAL(pull<data::type>(), data::type::vector);
  CHECK_EQUAL(pull<uint32_t>(), 3u);
  CHECK_EQUAL(pull<data::type>(), data::type::integer);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 11u);
  CHECK_EQUAL(pull<data::type>(), data::type::real);
  CHECK(at_end());
}

CAF_TEST_FIXTURE_SCOPE_END()
