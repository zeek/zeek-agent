#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <caf/actor_system_config.hpp>
#pragma GCC diagnostic pop

namespace broker {

struct broker_options {
  /// If true, peer connections won't use SSL.
  bool disable_ssl = false;
  /// If true, endpoints will forward incoming messages to peers.
  bool forward = true;
  /// TTL to insert into forwarded messages. Messages will be droppped once
  /// they have traversed more than this many hops. Note that the 1st
  /// receiver inserts the TTL (not the sender!). The 1st receiver does
  /// already count against the TTL.
  unsigned int ttl = 20;
  /// Whether to use real/wall clock time for data store time-keeping
  /// tasks or whether the application will simulate time on its own.
  bool use_real_time = true;

  broker_options() {}
};

/// Provides an execution context for brokers.
class configuration : public caf::actor_system_config {
public:
  /// Default-constructs a configuration.
  configuration(broker_options opts = broker_options());

  /// Constructs a configuration from the command line.
  configuration(int argc, char** argv);

  /// Returns default Broker options and flags.
  const broker_options& options() const {
    return options_;
  }

  /// Adds all Broker message types to `cfg`.
  static void add_message_types(caf::actor_system_config& cfg);

private:
  broker_options options_;
};

} // namespace broker
