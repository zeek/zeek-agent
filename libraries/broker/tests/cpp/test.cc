#define CAF_TEST_NO_MAIN
#include <caf/test/unit_test_impl.hpp>

#include "test.hh"

#include <caf/defaults.hpp>
#include <caf/io/middleman.hpp>
#include <caf/io/network/test_multiplexer.hpp>
#include <caf/test/dsl.hpp>

using namespace caf;
using namespace broker;

base_fixture::base_fixture()
  : ep(make_config()),
    sys(ep.system()),
    self(sys),
    sched(dynamic_cast<scheduler_type&>(sys.scheduler())),
    credit_round_interval(
      get_or(sys.config(), "stream.credit-round-interval",
             caf::defaults::stream::credit_round_interval)) {
  // nop
}

base_fixture::~base_fixture() {
  run();
  // Our core might do some messaging in its dtor, hence we need to make sure
  // messages are handled when enqueued to avoid blocking.
  sched.inline_all_enqueues();
}

configuration base_fixture::make_config() {
  broker_options options;
  options.disable_ssl = true;
  configuration cfg{options};
  test_coordinator_fixture<configuration>::init_config(cfg);
  cfg.set("logger.verbosity", caf::atom("TRACE"));
  cfg.load<io::middleman, io::network::test_multiplexer>();
  return cfg;
}

void base_fixture::run() {
  while (sched.has_job() || sched.has_pending_timeout()) {
    sched.run();
    sched.trigger_timeouts();
  }
}

void base_fixture::consume_message() {
  if (!sched.try_run_once())
    CAF_FAIL("no message to consume");
}

int main(int argc, char** argv) {
  //if (! broker::logger::file(broker::logger::debug, "broker-unit-test.log"))
  //  return 1;
  return test::main(argc, argv);
}
