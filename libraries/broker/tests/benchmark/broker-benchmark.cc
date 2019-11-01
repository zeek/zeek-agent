#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <sys/time.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <caf/deep_to_string.hpp>
#include <caf/downstream.hpp>

#include "broker/configuration.hh"
#include "broker/convert.hh"
#include "broker/data.hh"
#include "broker/endpoint.hh"
#include "broker/publisher.hh"
#include "broker/status.hh"
#include "broker/status_subscriber.hh"
#include "broker/topic.hh"
#include "broker/zeek.hh"

using namespace broker;

namespace {

int event_type = 1;
double batch_rate = 1;
int batch_size = 1;
double rate_increase_interval = 0;
double rate_increase_amount = 0;
uint64_t max_received = 0;
uint64_t max_in_flight = 0;
bool server = false;
bool verbose = false;

// Global state
unsigned long total_recv;
unsigned long total_sent;
unsigned long last_sent;
double last_t;

std::atomic<size_t> num_events;

size_t reset_num_events() {
  auto result = num_events.load();
  if (result == 0)
    return 0;
  for (;;)
    if (num_events.compare_exchange_strong(result, 0))
      return result;
}

double current_time() {
  struct timeval tv;
  gettimeofday(&tv, 0);
  return double(tv.tv_sec) + double(tv.tv_usec) / 1e6;
}

static std::string random_string(int n) {
    static unsigned int i = 0;
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

     const size_t max_index = (sizeof(charset) - 1);
     char buffer[11];
     for ( unsigned int j = 0; j < sizeof(buffer) - 1; j++ )
    buffer[j] = charset[++i % max_index];
     buffer[sizeof(buffer) - 1] = '\0';

     return buffer;
}

static uint64_t random_count() {
    static uint64_t i = 0;
    return ++i;
}

vector createEventArgs() {
    switch ( event_type ) {
     case 1: {
         return std::vector<data>{42, "test"};
     }

     case 2: {
         // This resembles a line in conn.log.
         address a1;
         address a2;
         convert("1.2.3.4", a1);
         convert("3.4.5.6", a2);

         return vector{
             now(),
             random_string(10),
             vector{
                 a1,
                 port(4567, port::protocol::tcp),
                 a2,
                 port(80, port::protocol::tcp)
             },
             enum_value("tcp"),
             random_string(10),
             std::chrono::duration_cast<timespan>(std::chrono::duration<double>(3.14)),
             random_count(),
             random_count(),
             random_string(5),
             true,
             false,
             random_count(),
             random_string(10),
             random_count(),
             random_count(),
             random_count(),
             random_count(),
             set({random_string(10), random_string(10)})
        };
     }

     case 3: {
         table m;

         for ( int i = 0; i < 100; i++ ) {
             set s;
             for ( int j = 0; j < 10; j++ )
                 s.insert(random_string(5));
             m[random_string(15)] = s;
         }

         return vector{now(), m};
     }

     default:
       std::cerr << "invalid event type" << std::endl;
       abort();
    }
}

void send_batch(endpoint& ep, publisher& p) {
  auto name = "event_" + std::to_string(event_type);
  vector batch;
  for (int i = 0; i < batch_size; i++) {
    auto ev = zeek::Event(std::string(name), createEventArgs());
    batch.emplace_back(std::move(ev));
  }
  total_sent += batch.size();
  p.publish(std::move(batch));
}

void receivedStats(endpoint& ep, data x) {
  // Example for an x: '[1, 1, [stats_update, [1ns, 1ns, 0]]]'.
  // We are only interested in the '[1ns, 1ns, 0]' part.
  auto xvec = caf::get<vector>(x);
  auto yvec = caf::get<vector>(xvec[2]);
  auto rec = caf::get<vector>(yvec[1]);

  double t;
  convert(caf::get<timestamp>(rec[0]), t);

  double dt_recv;
  convert(caf::get<timespan>(rec[1]), dt_recv);

  auto ev1 = caf::get<count>(rec[2]);
  auto all_recv = ev1;
  total_recv += ev1;

  auto all_sent = (total_sent - last_sent);

  double now;
  convert(broker::now(), now);
  double dt_sent = (now - last_t);

  auto recv_rate = (double(all_recv) / dt_recv);
  auto send_rate = double(total_sent - last_sent) / dt_sent;
  auto in_flight = (total_sent - total_recv);

  std::cerr << to_string(t) << " "
            << "[batch_size=" << batch_size << "] "
            << "in_flight=" << in_flight << " "
            << "d_t=" << dt_recv << " "
            << "d_recv=" << all_recv << " "
            << "d_sent=" << all_sent << " "
            << "total_recv=" << total_recv << " "
            << "total_sent=" << total_sent << " "
            << "[sending at " << send_rate << " ev/s, receiving at "
            << recv_rate << " ev/s " << std::endl;

  last_t = now;
  last_sent = total_sent;

  if (max_received && total_recv > max_received) {
    zeek::Event ev("quit_benchmark", std::vector<data>{});
    ep.publish("/benchmark/terminate", ev);
    sleep(2); // Give clients a bit.
    exit(0);
  }

  static int max_exceeded_counter = 0;
  if (max_in_flight && in_flight > max_in_flight) {

    if (++max_exceeded_counter >= 5) {
      std::cerr << "max-in-flight exceeded for 5 subsequent batches"
                << std::endl;
      exit(1);
    }
  } else
    max_exceeded_counter = 0;
}

void client_mode(endpoint& ep, const std::string& host, int port) {
  // Make sure to receive status updates.
  auto ss = ep.make_status_subscriber(true);
  // Subscribe to /benchmark/stats to print server updates.
  ep.subscribe_nosync(
    {"/benchmark/stats"},
    [](caf::unit_t&) {
      // nop
    },
    [&](caf::unit_t&, data_message x) {
      // Print everything we receive.
      receivedStats(ep, move_data(x));
    },
    [](caf::unit_t&, const caf::error&) {
      // nop
    });
  // Publish events to /benchmark/events.
  auto p = ep.make_publisher("/benchmark/events");
  // Connect to remote peer.
  if (verbose)
    std::cout << "*** init peering: host = " << host << ", port = " << port
              << std::endl;
  auto res = ep.peer(host, port, timeout::seconds(1));
  if (!res) {
    std::cerr << "unable to peer to " << host << " on port " << port
              << std::endl;
    return;
  }
  if (verbose)
    std::cout << "*** endpoint is now peering to remote" << std::endl;
  // Publish one message per interval.
  using std::chrono::duration_cast;
  using fractional_second = std::chrono::duration<double>;
  fractional_second fractional_inc_interval{rate_increase_interval};
  auto inc_interval = duration_cast<timespan>(fractional_inc_interval);
  timestamp timeout = std::chrono::system_clock::now();
  auto interval = duration_cast<timespan>(std::chrono::seconds(1));
  interval /= batch_rate;
  auto interval_timeout = timeout + interval;
  for (;;) {
    // Sleep until next timeout.
    timeout += interval;
    std::this_thread::sleep_until(timeout);
    // Ship some data.
    if (p.free_capacity() > 1) {
      send_batch(ep, p);
    } else {
      std::cout << "*** skip batch: publisher queue full" << std::endl;
    }
    // Increase batch size when reaching interval_timeout.
    if (rate_increase_interval > 0 && rate_increase_amount > 0) {
      auto now = std::chrono::system_clock::now();
      if (now >= interval_timeout) {
        batch_size += rate_increase_amount;
        interval_timeout += interval;
      }
    }
    // Print status events.
    auto status_events = ss.poll();
    if (verbose)
      for (auto& ev : status_events)
        std::cout << caf::deep_to_string(ev) << std::endl;
  }
}

// This mode mimics what benchmark.bro does.
void server_mode(endpoint& ep, const std::string& iface, int port) {
  // Make sure to receive status updates.
  auto ss = ep.make_status_subscriber(true);
  // Subscribe to /benchmark/events.
  ep.subscribe_nosync(
    {"/benchmark/events"},
    [](caf::unit_t&) {
      // nop
    },
    [&](caf::unit_t&, data_message x) {
      auto msg = move_data(x);
      // Count number of events (counts each element in a batch as one event).
      if (zeek::Message::type(msg) == zeek::Message::Type::Event) {
        ++num_events;
      } else if (zeek::Message::type(msg) == zeek::Message::Type::Batch) {
        zeek::Batch batch(std::move(msg));
        num_events += batch.batch().size();
      } else {
        std::cerr << "unexpected message type" << std::endl;
        exit(1);
      }
    },
    [](caf::unit_t&, const caf::error&) {
      // nop
    });
  // Listen on /benchmark/terminate for stop message.
  std::atomic<bool> terminate{false};
  ep.subscribe_nosync(
    {"/benchmark/terminate"},
    [](caf::unit_t&) {
      // nop
    },
    [&](caf::unit_t&, data_message) {
      // Any message on this topic triggers termination.
      terminate = true;
    },
    [](caf::unit_t&, const caf::error&) {
      // nop
    });
  // Start listening for peers.
  ep.listen(iface, port);
  // Collects stats once per second until receiving stop message.
  using std::chrono::duration_cast;
  timestamp timeout = std::chrono::system_clock::now();
  auto last_time = timeout;
  while (!terminate) {
    // Sleep until next timeout.
    timeout += std::chrono::seconds(1);
    std::this_thread::sleep_until(timeout);
    // Generate and publish zeek event.
    timestamp now = std::chrono::system_clock::now();
    auto stats = vector{now, now - last_time, count{reset_num_events()}};
    if (verbose)
      std::cout << "stats: " << caf::deep_to_string(stats) << std::endl;
    zeek::Event ev("stats_update", vector{std::move(stats)});
    ep.publish("/benchmark/stats", std::move(ev));
    // Advance time and print status events.
    last_time = now;
    auto status_events = ss.poll();
    if (verbose)
      for (auto& ev : status_events)
        std::cout << caf::deep_to_string(ev) << std::endl;
  }
  std::cout << "received stop message on /benchmark/terminate" << std::endl;
}

struct config : configuration {
  config(){
    opt_group{custom_options_, "global"}
      .add(event_type, "event-type,t",
           "1 (vector, default) | 2 (conn log entry) | 3 (table)")
      .add(batch_rate, "batch-rate,r", "batches/sec (default: 1)")
      .add(batch_size, "batch-size,s", "events per batch (default: 1)")
      .add(rate_increase_interval, "batch-size-increase-interval,i",
           "interval for increasing the batch size (in seconds)")
      .add(rate_increase_amount, "batch-size-increase-amount,a",
           "additional batch size per interval")
      .add(max_received, "max-received,m", "stop benchmark after given count")
      .add(max_in_flight, "max-in-flight,f", "report when exceeding this count")
      .add(server, "server", "run in server mode")
      .add(verbose, "verbose", "enable status output");
  }

  std::string help_text() const {
    return custom_options_.help_text();
  }
};

void usage(const config& cfg, const char* cmd_name) {
  std::cerr << "Usage: " << cmd_name
            << " [<options>] <zeek-host>[:<port>] | [--disable-ssl] --server "
               "<interface>:port\n\n"
            << cfg.help_text();
}

} // namespace

int main(int argc, char** argv) {
  config cfg;
  if (auto err = cfg.parse(argc,argv)){
    std::cerr << "*** invalid command line: " << cfg.render(err) << "\n\n";
    usage(cfg, argv[0]);
    return EXIT_FAILURE;
  }
  if (cfg.cli_helptext_printed)
    return EXIT_SUCCESS;
  if (cfg.remainder.size() != 1) {
    std::cerr << "*** too many arguments\n\n";
    usage(cfg, argv[0]);
    return EXIT_FAILURE;
  }
  // Local variables configurable via CLI.
  auto arg = cfg.remainder[0];
  auto separator = arg.find(':');
  if (separator == std::string::npos) {
    std::cerr << "*** invalid argument\n\n";
    usage(cfg, argv[0]);
    return EXIT_FAILURE;
  }
  std::string host = arg.substr(0, separator);
  uint16_t port = 9999;
  try {
    auto str_port = arg.substr(separator + 1);
    if (!str_port.empty()) {
      auto int_port = std::stoi(str_port);
      if (int_port < 0 || int_port > std::numeric_limits<uint16_t>::max())
        throw std::out_of_range("not an uint16_t");
      port = static_cast<uint16_t>(int_port);
    }
  } catch (std::exception& e) {
    std::cerr << "*** invalid port: " << e.what() << "\n\n";
    usage(cfg, argv[0]);
    return EXIT_FAILURE;
  }
  // Run benchmark.
  endpoint ep(std::move(cfg));
  if (server)
    server_mode(ep, host, port);
  else
    client_mode(ep, host, port);
  return EXIT_SUCCESS;
}
