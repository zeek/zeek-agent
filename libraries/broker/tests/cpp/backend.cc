#define SUITE backend

#include "broker/backend.hh"

#include "test.hh"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "broker/backend_options.hh"
#include "broker/data.hh"
#include "broker/detail/abstract_backend.hh"
#include "broker/detail/assert.hh"
#include "broker/detail/filesystem.hh"
#include "broker/detail/make_backend.hh"
#include "broker/detail/make_unique.hh"
#include "broker/detail/memory_backend.hh"
#include "broker/detail/rocksdb_backend.hh"
#include "broker/detail/sqlite_backend.hh"
#include "broker/error.hh"
#include "broker/expected.hh"
#include "broker/optional.hh"
#include "broker/snapshot.hh"
#include "broker/time.hh"

using namespace broker;

namespace {

template <class T>
bool all_equal(const std::vector<T>& xs) {
  auto i = std::adjacent_find(xs.begin(), xs.end(), std::not_equal_to<T>{});
  return i == xs.end();
}

class meta_backend : public detail::abstract_backend {
public:
  meta_backend(backend_options opts) {
    backends_.push_back(detail::make_backend(memory, opts));
    auto& path = caf::get<std::string>(opts["path"]);
    auto base = path;
    // Make sure both backends have their own filesystem storage to work with.
    path += ".sqlite";
    paths_.push_back(path);
    detail::remove_all(path);
    backends_.push_back(detail::make_backend(sqlite, opts));
#ifdef BROKER_HAVE_ROCKSDB
    path = base + ".rocksdb";
    paths_.push_back(path);
    detail::remove_all(path);
    backends_.push_back(detail::make_backend(rocksdb, opts));
#endif
  }

  ~meta_backend() {
    for (auto& path : paths_)
      detail::remove_all(path);
  }

  expected<void> put(const data& key, data value,
                     optional<timestamp> expiry) override {
    return perform<void>(
      [&](detail::abstract_backend& backend) {
        return backend.put(key, value, expiry);
      }
    );
  }

  expected<void> add(const data& key, const data& value, data::type init_type,
                     optional<timestamp> expiry) override {
    return perform<void>(
      [&](detail::abstract_backend& backend) {
        return backend.add(key, value, init_type, expiry);
      }
    );
  }

  expected<void> subtract(const data& key, const data& value,
                        optional<timestamp> expiry) override {
    return perform<void>(
      [&](detail::abstract_backend& backend) {
        return backend.subtract(key, value, expiry);
      }
    );
  }

  expected<void> erase(const data& key) override {
    return perform<void>(
      [&](detail::abstract_backend& backend) {
        return backend.erase(key);
      }
    );
  }

  expected<void> clear() override {
    return perform<void>(
      [&](detail::abstract_backend& backend) {
        return backend.clear();
      }
    );
  }

  expected<bool> expire(const data& key, timestamp ts) override {
    return perform<bool>(
      [&](detail::abstract_backend& backend) {
        return backend.expire(key, ts);
      }
    );
  }

  expected<data> get(const data& key) const override {
    return perform<data>(
      [&](detail::abstract_backend& backend) {
        return backend.get(key);
      }
    );
  }

  expected<data> get(const data& key, const data& value) const override {
    return perform<data>(
      [&](detail::abstract_backend& backend) {
        return backend.get(key, value);
      }
    );
  }

  expected<data> keys() const override {
    return perform<data>(
      [&](detail::abstract_backend& backend) {
        return backend.keys();
      }
    );
  }

  expected<bool> exists(const data& key) const override {
    return perform<bool>(
      [&](detail::abstract_backend& backend) {
        return backend.exists(key);
      }
    );
  }

  expected<uint64_t> size() const override {
    return perform<uint64_t>(
      [](detail::abstract_backend& backend) {
        return backend.size();
      }
    );
  }

  expected<broker::snapshot> snapshot() const override {
    return perform<broker::snapshot>(
      [](detail::abstract_backend& backend) {
        return backend.snapshot();
      }
    );
  }

  expected<broker::detail::expirables> expiries() const override {
    return perform<broker::detail::expirables>(
      [](detail::abstract_backend& backend) {
        return backend.expiries();
      }
    );
  }

private:
  template <class T, class F>
  expected<T> perform(F f) {
    std::vector<expected<T>> xs;
    for (auto& backend : backends_)
      xs.push_back(f(*backend));
    if (!all_equal(xs))
      return ec::unspecified;
    return std::move(xs.front());
  }

  template <class T, class F>
  expected<T> perform(F f) const {
    return const_cast<meta_backend*>(this)->perform<T>(f); // lazy
  }

  std::vector<std::unique_ptr<detail::abstract_backend>> backends_;
  std::vector<std::string> paths_;
};

struct fixture {
  static constexpr char filename[] = "/tmp/broker-unit-test-backend";

  fixture() {
    auto opts = backend_options{{"path", filename}};
    backend = std::make_unique<meta_backend>(std::move(opts));
  }

  std::unique_ptr<detail::abstract_backend> backend;
};

constexpr char fixture::filename[];

} // namespace <anonymous>

FIXTURE_SCOPE(backend_tests, fixture)

TEST(put/get) {
  auto put = backend->put("foo", 7);
  REQUIRE(put);
  auto get = backend->get("foo");
  REQUIRE(get);
  CHECK_EQUAL(*get, data{7});
  MESSAGE("overwrite");
  put = backend->put("foo", 42);
  REQUIRE(put);
  get = backend->get("foo");
  REQUIRE(get);
  CHECK_EQUAL(*get, data{42});
  MESSAGE("no key");
  get = backend->get("bar");
  REQUIRE(!get);
  CHECK_EQUAL(get.error(), ec::no_such_key);
}

TEST(add/remove) {
  backend->put("foo", 0);
  auto add = backend->add("foo", 42, data::type::integer);
  REQUIRE(add);
  auto get = backend->get("foo");
  REQUIRE(get);
  CHECK_EQUAL(*get, data{42});

  auto erase = backend->erase("foo");
  REQUIRE(erase); // succeeds independent of key existence

  auto remove = backend->subtract("foo", 42);
  REQUIRE(!remove);
  CHECK_EQUAL(remove, ec::no_such_key);

  auto put = backend->put("foo", 42);
  MESSAGE("add");
  add = backend->add("foo", 2, data::type::integer);
  REQUIRE(add);
  get = backend->get("foo");
  REQUIRE(get);
  CHECK_EQUAL(*get, data{44});
  MESSAGE("remove");
  remove = backend->subtract("foo", "bar");
  REQUIRE(!remove);
  CHECK_EQUAL(remove, ec::type_clash);
  remove = backend->subtract("foo", 10);
  REQUIRE(remove);
  get = backend->get("foo");
  REQUIRE(get);
  CHECK_EQUAL(*get, data{34});
}

TEST(erase/exists) {
  using namespace std::chrono;
  auto exists = backend->exists("foo");
  REQUIRE(exists);
  CHECK(!*exists);
  auto erase = backend->erase("foo");
  REQUIRE(erase); // succeeds independent of key existence
  auto put = backend->put("foo", "bar", broker::now() + seconds{42});
  REQUIRE(put);
  exists = backend->exists("foo");
  REQUIRE(exists);
  CHECK(*exists);
  put = backend->put("bar", vector{1, 2, 3});
  REQUIRE(put);
  exists = backend->exists("bar");
  REQUIRE(exists);
  CHECK(*exists);
  erase = backend->erase("foo");
  REQUIRE(erase);
  erase = backend->erase("bar");
  REQUIRE(erase);
}

TEST(clear/keys) {
  using namespace std::chrono;
  auto put = backend->put("foo", "1");
  REQUIRE(put);
  put = backend->put("bar", "2");
  REQUIRE(put);
  auto size = backend->size();
  REQUIRE(size);
  CHECK_EQUAL(*size, 2u);
  auto keys = backend->keys();
  std::set<data> x{data("foo"), data("bar")};
  CHECK_EQUAL(*keys, x);
  auto clear = backend->clear();
  REQUIRE(clear);
  size = backend->size();
  REQUIRE(size);
  CHECK_EQUAL(*size, 0u);
}

TEST(expiration with expiry) {
  using namespace std::chrono;
  auto put = backend->put("foo", "bar", broker::now() + milliseconds(50));
  REQUIRE(put);
  std::this_thread::sleep_for(milliseconds(10));
  auto expire = backend->expire("foo", broker::now());
  REQUIRE(expire);
  CHECK(!*expire); // too early
  auto exists = backend->exists("foo");
  REQUIRE(exists);
  CHECK(*exists);
  std::this_thread::sleep_for(milliseconds(40));
  expire = backend->expire("foo", broker::now());
  REQUIRE(expire);
  CHECK(*expire); // success: time of call > expiry
  exists = backend->exists("foo");
  REQUIRE(exists);
  CHECK(!*exists); // element removed
}

TEST(expiration without expiry) {
  auto put = backend->put("foo", 4.2);
  REQUIRE(put);
  auto expire = backend->expire("foo", broker::now());
  REQUIRE(expire);
  REQUIRE(!*expire); // no expiry with key associated
}

TEST(size/snapshot) {
  using namespace std::chrono;
  auto put = backend->put("foo", "bar");
  REQUIRE(put);
  put = backend->put("bar", 4.2, broker::now() + seconds{10});
  REQUIRE(put);
  put = backend->put("baz", table{{"foo", true}, {"bar", false}});
  REQUIRE(put);
  auto size = backend->size();
  REQUIRE(size);
  CHECK_EQUAL(*size, 3u);
  auto ss = backend->snapshot();
  REQUIRE(ss);
  CHECK_EQUAL(ss->size(), *size);
  CHECK_EQUAL(ss->count("foo"), 1u);
}

FIXTURE_SCOPE_END()
