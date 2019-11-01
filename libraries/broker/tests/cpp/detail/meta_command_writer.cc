#define SUITE meta_command_writer

#include "broker/detail/meta_command_writer.hh"

#include "test.hh"

#include <vector>

#include <caf/binary_deserializer.hpp>
#include <caf/binary_serializer.hpp>

#include "broker/data.hh"

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
  void push(T&& x) {
    internal_command cmd{std::forward<T>(x)};
    detail::meta_command_writer writer{sink};
    CHECK_EQUAL(writer(cmd), caf::none);
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

CAF_TEST_FIXTURE_SCOPE(meta_command_writer_tests, fixture)

CAF_TEST(default constructed command) {
  push(internal_command{});
  CHECK_EQUAL(pull<internal_command::type>(), internal_command::type::none);
  CHECK(at_end());
}

CAF_TEST(put_command) {
  push(put_command{data{"hello"}, data{"broker"}, nil});
  CHECK_EQUAL(pull<internal_command::type>(),
              internal_command::type::put_command);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 5u);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 6u);
  CHECK(at_end());
}

CAF_TEST(put_unique_command) {
  push(put_unique_command{data{"hello"}, data{"broker"}, nil, nullptr, 0});
  CHECK_EQUAL(pull<internal_command::type>(),
              internal_command::type::put_unique_command);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 5u);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 6u);
  CHECK(at_end());
}

CAF_TEST(erase_command) {
  push(erase_command{data{"foobar"}});
  CHECK_EQUAL(pull<internal_command::type>(),
              internal_command::type::erase_command);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 6u);
  CHECK(at_end());
}

CAF_TEST(add_command) {
  push(add_command{data{"key"}, data{"value"}, data::type::table, nil});
  CHECK_EQUAL(pull<internal_command::type>(),
              internal_command::type::add_command);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 3u);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 5u);
  CHECK_EQUAL(pull<data::type>(), data::type::table);
  CHECK(at_end());
}

CAF_TEST(subtract_command) {
  push(subtract_command{data{"key"}, data{"value"}, nil});
  CHECK_EQUAL(pull<internal_command::type>(),
              internal_command::type::subtract_command);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 3u);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 5u);
  CHECK(at_end());
}

CAF_TEST(snapshot_command) {
  push(snapshot_command{nullptr, nullptr});
  CHECK_EQUAL(pull<internal_command::type>(),
              internal_command::type::snapshot_command);
  CHECK(at_end());
}

CAF_TEST(snapshot_sync_command) {
  push(snapshot_sync_command{nullptr});
  CHECK_EQUAL(pull<internal_command::type>(),
              internal_command::type::snapshot_sync_command);
  CHECK(at_end());
}

CAF_TEST(set_command) {
  push(set_command{{{data{"key"}, data{"value"}}}});
  CHECK_EQUAL(pull<internal_command::type>(),
              internal_command::type::set_command);
  CHECK_EQUAL(pull<uint32_t>(), 1u);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 3u);
  CHECK_EQUAL(pull<data::type>(), data::type::string);
  CHECK_EQUAL(pull<uint32_t>(), 5u);
  CHECK(at_end());
}

CAF_TEST_FIXTURE_SCOPE_END()
