#define SUITE store

#include "broker/store.hh"

#include "test.hh"

#include <chrono>
#include <thread>
#include <utility>

#include "broker/backend.hh"
#include "broker/backend_options.hh"
#include "broker/data.hh"
#include "broker/endpoint.hh"
#include "broker/error.hh"

using namespace broker;

TEST(default construction) {
  store{};
  store::proxy{};
}

TEST(backend option passing) {
  endpoint ep;
  auto opts = backend_options{{"foo", 4.2}};
  auto ds = ep.attach_master("lord", memory, std::move(opts));
  REQUIRE(ds);
}

TEST(master operations) {
  endpoint ep;
  auto ds = ep.attach_master("kono", memory);
  REQUIRE(ds);
  MESSAGE("put");
  ds->put("foo", 42);
  REQUIRE_EQUAL(value_of(ds->get("foo")), data{42});
  REQUIRE_EQUAL(error_of(ds->get("bar")), error{ec::no_such_key});
  REQUIRE_EQUAL(ds->exists("foo"), true);
  REQUIRE_EQUAL(ds->exists("bar"), false);
  MESSAGE("erase");
  ds->erase("foo");
  REQUIRE_EQUAL(ds->get("foo"), error{ec::no_such_key});

  MESSAGE("increment");
  ds->increment("foo", 13u);
  REQUIRE_EQUAL(value_of(ds->get("foo")), data{13u});

  ds->increment("foo", 1u);
  REQUIRE_EQUAL(value_of(ds->get("foo")), data{14u});

  MESSAGE("decrement");
  ds->decrement("foo", 1u);
  REQUIRE_EQUAL(value_of(ds->get("foo")), data{13u});

  MESSAGE("append");
  ds->put("foo", "b");
  ds->append("foo", "a");
  ds->append("foo", "r");
  REQUIRE_EQUAL(value_of(ds->get("foo")), data{"bar"});
  MESSAGE("insert_into");
  ds->put("foo", set{1, 3});
  ds->insert_into("foo", 2);
  REQUIRE_EQUAL(value_of(ds->get("foo")), data(set{1, 2, 3}));
  MESSAGE("remove_from");
  ds->remove_from("foo", 2);
  REQUIRE_EQUAL(value_of(ds->get("foo")), data(set{1, 3}));
  MESSAGE("push");
  ds->put("foo", vector{1, 2});
  ds->push("foo", 3);
  REQUIRE_EQUAL(value_of(ds->get("foo")), data(vector{1, 2, 3}));
  MESSAGE("pop");
  ds->pop("foo");
  REQUIRE_EQUAL(value_of(ds->get("foo")), data(vector{1, 2}));
  MESSAGE("get overload");
  ds->put("foo", set{2, 3});
  REQUIRE_EQUAL(ds->get_index_from_value("foo", 1), false);
  REQUIRE_EQUAL(ds->get_index_from_value("foo", 2), true);
  MESSAGE("keys");
  REQUIRE_EQUAL(value_of(ds->keys()), data(set{"foo"}));
}

TEST(clone operations - same endpoint) {
  endpoint ep;
  auto m = ep.attach_master("vulcan", memory);
  MESSAGE("master PUT");
  m->put("key", "value");
  REQUIRE(m);
  auto c = ep.attach_clone("vulcan");
  REQUIRE(!c);
}

TEST(expiration) {
  using std::chrono::milliseconds;
  endpoint ep;
  auto m = ep.attach_master("grubby", memory);
  REQUIRE(m);
  auto expiry = milliseconds(600);
  m->put("foo", 42, expiry);
  // Check within validity interval.
  std::this_thread::sleep_for(milliseconds(50));
  CHECK_EQUAL(value_of(m->get("foo")), data{42});
  std::this_thread::sleep_for(milliseconds(1000));
  // Check after expiration.
  CHECK_EQUAL(error_of(m->get("foo")), ec::no_such_key);
}

TEST(proxy) {
  endpoint ep;
  auto m = ep.attach_master("puneta", memory);
  REQUIRE(m);
  auto proxy = store::proxy{*m};
  REQUIRE(proxy.mailbox().empty());
  REQUIRE_EQUAL(proxy.mailbox().size(), 0u);
  m->put("foo", 42);
  MESSAGE("master: issue queries");
  auto id = proxy.get("foo");
  CHECK_EQUAL(id, 1u);
  id = proxy.get("bar");
  CHECK_EQUAL(id, 2u);
  MESSAGE("master: collect responses");
  auto resp = proxy.receive();
  CHECK_EQUAL(resp.id, 1u);
  REQUIRE_EQUAL(value_of(resp.answer), data{42});
  resp = proxy.receive();
  CHECK_EQUAL(resp.id, 2u);
  REQUIRE_EQUAL(resp.answer, error{ec::no_such_key});
  auto key_id = proxy.keys();
  auto key_resp = proxy.receive();
  CAF_REQUIRE_EQUAL(key_resp.id, key_id);
  CAF_REQUIRE_EQUAL(value_of(key_resp.answer), data(set{"foo"}));
}
