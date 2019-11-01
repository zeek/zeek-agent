#define SUITE generator_file_writer

#include "broker/detail/generator_file_writer.hh"

#include "test.hh"

#include <unistd.h>

#include "broker/detail/generator_file_reader.hh"

using namespace broker;

using caf::holds_alternative;

namespace {

struct fixture {
  fixture() {
    // Write something to read.
    char fname[] = "/tmp/broker.test.XXXXXX";
    auto fd = mkstemp(fname);
    if (fd == -1)
      ERROR("unable to generate a temporary file name");
    else {
      close(fd);
      file_name = fname;
    }
  }

  ~fixture() {
    if (!file_name.empty())
      unlink(file_name.c_str());
  }

  std::string file_name;
};

} // namespace

CAF_TEST_FIXTURE_SCOPE(generator_file_writer_tests, fixture)

CAF_TEST(data_message roundtrip with generator_file_reader) {
  auto x = vector{1, 2, "a", "bc"};
  auto x_msg = make_data_message("foo/bar", x);
  {
    auto out = detail::make_generator_file_writer(file_name);
    *out << x_msg;
  }
  // Read back from file.
  auto reader = detail::make_generator_file_reader(file_name);
  REQUIRE_NOT_EQUAL(reader, nullptr);
  caf::variant<data_message, command_message> y_msg;
  CHECK_EQUAL(reader->read(y_msg), caf::none);
  CHECK_EQUAL(reader->at_end(), true);
  CHECK_EQUAL(get_topic(y_msg), topic{"foo/bar"});
  REQUIRE(is_data_message(y_msg));
  data y_data = get_data(get<data_message>(y_msg));
  REQUIRE(holds_alternative<vector>(y_data));
  auto& y = get<vector>(y_data);
  REQUIRE_EQUAL(x.size(), y.size());
  CHECK(holds_alternative<integer>(y[0]));
  CHECK(holds_alternative<integer>(y[1]));
  REQUIRE(holds_alternative<std::string>(y[2]));
  CHECK_EQUAL(get<std::string>(x[2]).size(), get<std::string>(y[2]).size());
  REQUIRE(holds_alternative<std::string>(y[3]));
  CHECK_EQUAL(get<std::string>(x[3]).size(), get<std::string>(y[3]).size());
  CHECK_EQUAL(reader->read(y_msg), ec::end_of_file);
}

CAF_TEST(command_message roundtrip with generator_file_reader) {
  auto x = vector{1, 2, "a", "bc"};
  auto x_msg = make_data_message("foo/bar", x);
  {
    auto out = detail::make_generator_file_writer(file_name);
    *out << x_msg;
  }
  // Read back from file.
  auto reader = detail::make_generator_file_reader(file_name);
  REQUIRE_NOT_EQUAL(reader, nullptr);
  caf::variant<data_message, command_message> y_msg;
  CHECK_EQUAL(reader->read(y_msg), caf::none);
  CHECK_EQUAL(reader->at_end(), true);
  CHECK_EQUAL(get_topic(y_msg), topic{"foo/bar"});
  REQUIRE(is_data_message(y_msg));
  data y_data = get_data(get<data_message>(y_msg));
  REQUIRE(holds_alternative<vector>(y_data));
  auto& y = get<vector>(y_data);
  REQUIRE_EQUAL(x.size(), y.size());
  CHECK(holds_alternative<integer>(y[0]));
  CHECK(holds_alternative<integer>(y[1]));
  REQUIRE(holds_alternative<std::string>(y[2]));
  CHECK_EQUAL(get<std::string>(x[2]).size(), get<std::string>(y[2]).size());
  REQUIRE(holds_alternative<std::string>(y[3]));
  CHECK_EQUAL(get<std::string>(x[3]).size(), get<std::string>(y[3]).size());
  CHECK_EQUAL(reader->read(y_msg), ec::end_of_file);
}

CAF_TEST_FIXTURE_SCOPE_END()
