// This suite is a test ensuring SSL authentication works as expected.
#define SUITE ssl

#include "test.hh"

#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "broker/configuration.hh"
#include "broker/data.hh"
#include "broker/endpoint.hh"
#include "broker/subscriber.hh"
#include "broker/topic.hh"

using namespace broker;

namespace {

configuration make_config(std::string cert_id) {
  configuration cfg;
  cfg.parse(caf::test::engine::argc(), caf::test::engine::argv());
  // cfg.set("scheduler.policy", caf::atom("testing"));
  cfg.set("logger.inline-output",  true);

//  cfg.scheduler_policy = caf::atom("testing");
  if ( cert_id.size() ) {
    auto test_dir = getenv("BROKER_TEST_DIR");
    CAF_REQUIRE(test_dir);
    auto cd = std::string(test_dir) + "/cpp/certs/";
    cfg.set("openssl.cafile", cd + "ca.pem");
    cfg.set("openssl.certificate", cd + "cert." + cert_id + ".pem");
    cfg.set("openssl.key", cd + "key." + cert_id + ".pem");
    MESSAGE("using certififcate " << cfg.openssl_certificate << ", key " << cfg.openssl_key);
  }
  return cfg;
}

// Holds state for individual peers. We use one fixture per simulated peer.
struct peer_fixture {
  // Identifies this fixture in the parent's `peers` map.
  std::string name;

  // Each peer is an endpoint.
  endpoint ep;

  // Initializes this peer and registers it at parent.
  peer_fixture(std::string peer_name, configuration config)
    : name(std::move(peer_name)),
      ep(std::move(config)){}
};

// A fixture for testing SSL authentication.
struct ssl_auth_fixture {
  peer_fixture mercury_auth;
  peer_fixture venus_auth;
  peer_fixture earth_no_auth;
  peer_fixture earth_wrong_auth;

  ssl_auth_fixture()
    : mercury_auth("mercury_auth", make_config("1")),
      venus_auth("venus_auth", make_config("2")),
      earth_no_auth("earth_no_auth", make_config("")),
      earth_wrong_auth("earth_wrong_auth", make_config("self-signed")) {
  }
};

} // namespace <anonymous>

CAF_TEST_FIXTURE_SCOPE(ssl_auth_use_cases, ssl_auth_fixture)

CAF_TEST(authenticated_session) {
MESSAGE("prepare authenticated connection");
  auto mercury_auth_es = mercury_auth.ep.make_subscriber({"/broker/test"});
  auto venus_auth_es = venus_auth.ep.make_subscriber({"/broker/test"});

  MESSAGE("mercury_auth listen");
  auto p = mercury_auth.ep.listen("127.0.0.1", 0);
  MESSAGE("venus_auth peer with mecury_auth on port " << p);
  auto b = venus_auth.ep.peer("127.0.0.1", p);
  CAF_REQUIRE(b);

  data_message ping{"/broker/test", "ping"};
  data_message pong{"/broker/test", "pong"};

  MESSAGE("mercury_auth sending ping");
  mercury_auth.ep.publish(ping);
  MESSAGE("venus_auth waiting for ping");
  CAF_CHECK_EQUAL(venus_auth_es.get(), ping);
  CAF_CHECK(mercury_auth_es.poll().empty());
  CAF_CHECK(venus_auth_es.poll().empty());

  MESSAGE("venus_auth sending pong");
  venus_auth.ep.publish(pong);
  MESSAGE("mercury_auth waiting for pong");
  CAF_CHECK_EQUAL(mercury_auth_es.get(), pong);
  CAF_CHECK(mercury_auth_es.poll().empty());
  CAF_CHECK(venus_auth_es.poll().empty());

  MESSAGE("disconnect venus_auth from mercury_auth");
  venus_auth.ep.unpeer("mercury", 4040);
  MESSAGE("venus_auth to shutdown");
  venus_auth.ep.shutdown();
  MESSAGE("mercury_auth to shutdown");
  mercury_auth.ep.shutdown();
  MESSAGE("all done");
}

CAF_TEST(authenticated_failure_no_ssl_peer) {
  MESSAGE("prepare authenticated connection expected to fail");
  MESSAGE("earth_no_auth listen");
  auto p = earth_no_auth.ep.listen("127.0.0.1", 0);

  MESSAGE("venus_auth peer with earth_no_auth on port " << p);
  auto b = venus_auth.ep.peer("127.0.0.1", p, timeout::seconds(0));
  CAF_REQUIRE(not b);

  MESSAGE("venus_auth to shutdown");
  venus_auth.ep.shutdown();
  MESSAGE("earth_no_auth to shutdown");
  earth_no_auth.ep.shutdown();
}

CAF_TEST(authenticated_failure_wrong_ssl_peer) {
  MESSAGE("prepare authenticated connection expected to fail");
  MESSAGE("earth_wrong_auth listen");
  auto p = earth_wrong_auth.ep.listen("127.0.0.1", 0);

  MESSAGE("venus_auth peer with earth_wrong_auth on port " << p);
  auto b = venus_auth.ep.peer("127.0.0.1", p, timeout::seconds(0));
  CAF_REQUIRE(not b);

  MESSAGE("venus_auth to shutdown");
  venus_auth.ep.shutdown();
  MESSAGE("earth_wrong_auth to shutdown");
  earth_wrong_auth.ep.shutdown();
}

CAF_TEST_FIXTURE_SCOPE_END()

