#include <cstdint>
#include <cstdlib>
#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <caf/atom.hpp>
#include <caf/config_option_adder.hpp>
#include <caf/downstream.hpp>
#include <caf/event_based_actor.hpp>
#include <caf/scoped_actor.hpp>

#include "broker/configuration.hh"
#include "broker/core_actor.hh"
#include "broker/data.hh"
#include "broker/endpoint.hh"
#include "broker/filter_type.hh"
#include "broker/topic.hh"

using std::cout;
using std::cerr;
using std::endl;

using namespace broker;

namespace {

class config : public configuration {
public:
  uint16_t port = 0;
  std::string host = "localhost";
  caf::atom_value mode;

  config() {
    opt_group{custom_options_, "global"}
    .add(mode, "mode,m", "one of 'sink', 'source', 'both', or 'fused'")
    .add(port, "port,p", "sets the port for listening or peering")
    .add(host, "host,o", "sets the peering with the sink");
  }
};

std::atomic<size_t> global_count;

void sink_mode(broker::endpoint& ep, topic t) {
  using namespace caf;
  auto worker = ep.subscribe(
    {t},
    [](caf::unit_t&) {
      // nop
    },
    [=](caf::unit_t&, std::vector<data_message>& xs) {
      global_count += xs.size();
    },
    [=](caf::unit_t&, const caf::error&) {
      // nop
    }
  );
  scoped_actor self{ep.system()};
  self->wait_for(worker);
}

void source_mode(broker::endpoint& ep, topic t) {
  using namespace caf;
  auto msg = make_data_message(t, "Lorem ipsum dolor sit amet.");
  auto worker = ep.publish_all(
    [](caf::unit_t&) {
      // nop
    },
    [=](caf::unit_t&, downstream<data_message>& out, size_t num) {
      for (size_t i = 0; i < num; ++i)
        out.push(msg);
      global_count += num;
    },
    [=](const caf::unit_t&) {
      return false;
    }
  );
  scoped_actor self{ep.system()};
  self->wait_for(worker);
}

void sender(caf::event_based_actor* self, caf::actor core, broker::topic t) {
  auto msg = std::make_pair(t, data{"Lorem ipsum dolor sit amet."});
  self->make_source(
    // Destination.
    core,
    // Initializer.
    [](caf::unit_t&) {},
    // Generator.
    [=](caf::unit_t&, caf::downstream<std::pair<topic, data>>& out, size_t n) {
      for (size_t i = 0; i < n; ++i)
        out.push(msg);
    },
    // Done predicate.
    [=](const caf::unit_t& msgs) { return false; });
}

caf::behavior receiver(caf::event_based_actor* self, caf::actor core,
                       broker::topic t) {
  self->send(core, broker::atom::join::value,
             broker::filter_type{std::move(t)});
  return {[=](caf::stream<std::pair<topic, data>> in) {
    return self->make_sink(
      // Source.
      in,
      // Initializer.
      [](caf::unit_t&) {
        // nop
      },
      // Consumer.
      [=](caf::unit_t&, std::vector<std::pair<topic, data>>& xs) {
        global_count += xs.size();
      },
      // Cleanup.
      [](caf::unit_t&, const caf::error&) {
        // nop
      }

    );
  }};
}

void rate_calculator() {
  // Counts consecutive rates that are 0.
  size_t zero_rates = 0;
  // Keeps track of the message count in our last iteration.
  size_t last_count = 0;
  // Used to compute absolute timeouts.
  auto t = std::chrono::steady_clock::now();
  // Stop after 2s of no activity.
  while (zero_rates < 2) {
    t += std::chrono::seconds(1);
    std::this_thread::sleep_until(t);
    auto count = global_count.load();
    auto rate = count - last_count;
    std::cout << rate << " msgs/s\n";
    last_count = count;
    if (rate == 0)
      ++zero_rates;
  }
}

} // namespace <anonymous>


int main(int argc, char** argv) {
  config cfg;
  cfg.parse(argc, argv);
  if (cfg.cli_helptext_printed)
    return EXIT_SUCCESS;
  auto mode = cfg.mode;
  auto port = cfg.port;
  auto host = cfg.host;
  topic foobar{"foo/bar"};
  std::thread t{rate_calculator};
  switch (caf::atom_uint(mode)) {
    default:
      std::cerr << "invalid mode: " << to_string(mode) << endl;
      return EXIT_FAILURE;
    case caf::atom_uint("source"): {
      broker::endpoint ep{std::move(cfg)};
      if (!ep.peer(host, port)) {
        std::cerr << "cannot peer to node: " << to_string(host) << " on port "
                  << port << endl;
        return EXIT_FAILURE;
      }
      source_mode(ep, foobar);
      break;
    }
    case caf::atom_uint("sink"): {
      broker::endpoint ep{std::move(cfg)};
      ep.listen({}, port);
      sink_mode(ep, foobar);
      break;
    }
    case caf::atom_uint("both"): {
      broker::endpoint ep1{std::move(cfg)};
      auto snk_port = ep1.listen({}, 0);
      std::thread source_thread{[argc, argv, host, snk_port, foobar] {
        config cfg2;
        cfg2.parse(argc, argv);
        broker::endpoint ep2{std::move(cfg2)};
        if (!ep2.peer(host, snk_port)) {
          std::cerr << "cannot peer to node: " << to_string(host) << " on port "
                    << snk_port << endl;
          return;
        }
        source_mode(ep2, foobar);
      }};
      sink_mode(ep1, foobar);
      source_thread.join();
      break;
    }
    case caf::atom_uint("fused"): {
      caf::actor_system sys{cfg};
      endpoint::clock clock{&sys, true};
      filter_type filter{foobar};
      auto core1 = sys.spawn(broker::core_actor, filter,
                             broker::broker_options{}, &clock);
      auto core2 = sys.spawn(broker::core_actor, filter,
                             broker::broker_options{}, &clock);
      anon_send(core1, atom::peer::value, core2);
      sys.spawn(sender, core1, foobar);
      sys.spawn(receiver, core2, foobar);
      caf::scoped_actor self{sys};
      self->wait_for(core1, core2);
    }
  }
  t.join();
  return EXIT_SUCCESS;
}
