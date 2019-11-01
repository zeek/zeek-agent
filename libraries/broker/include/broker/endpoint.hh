#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>

#include <caf/actor.hpp>
#include <caf/actor_clock.hpp>
#include <caf/event_based_actor.hpp>
#include <caf/message.hpp>
#include <caf/node_id.hpp>
#include <caf/stream.hpp>
#include <caf/timespan.hpp>
#include <caf/timestamp.hpp>

#include "broker/backend.hh"
#include "broker/backend_options.hh"
#include "broker/configuration.hh"
#include "broker/endpoint_info.hh"
#include "broker/expected.hh"
#include "broker/frontend.hh"
#include "broker/fwd.hh"
#include "broker/message.hh"
#include "broker/network_info.hh"
#include "broker/peer_info.hh"
#include "broker/status.hh"
#include "broker/status_subscriber.hh"
#include "broker/store.hh"
#include "broker/time.hh"
#include "broker/topic.hh"

namespace broker {

/// The main publish/subscribe abstraction. Endpoints can *peer* which each
/// other to exchange messages. When publishing a message though an endpoint,
/// all peers with matching subscriptions receive the message.
class endpoint {
public:
  // --- member types ----------------------------------------------------------

  using stream_type = caf::stream<data_message>;

  using actor_init_fun = std::function<void (caf::event_based_actor*)>;

  /// Custom clock for either running in realtime mode or advancing time
  /// manually.
  class clock {
  public:
    // -- member types ---------------------------------------------------------

    using mutex_type = std::mutex;

    using lock_type = std::unique_lock<mutex_type>;

    using pending_msg_type = std::pair<caf::actor, caf::message>;

    using pending_msgs_map_type = std::multimap<timestamp, pending_msg_type>;

    // --- construction and destruction ----------------------------------------

    clock(caf::actor_system* sys, bool use_real_time);

    // -- accessors ------------------------------------------------------------

    timestamp now() const noexcept;

    bool real_time() const noexcept {
      return real_time_;
    }

    // -- mutators -------------------------------------------------------------

    void advance_time(timestamp t);

    void send_later(caf::actor dest, timespan after, caf::message msg);

  private:
    /// Points to the host system.
    caf::actor_system* sys_;

    /// May be read from multiple threads.
    const bool real_time_;

    /// Nanoseconds since start of the epoch.
    std::atomic<timespan> time_since_epoch_;

    /// Guards pending_.
    mutex_type mtx_;

    /// Stores pending messages until they time out.
    pending_msgs_map_type pending_;

    /// Stores number of items in pending_.  We track it separately as
    /// a micro-optimization -- checking pending_.size() would require
    /// obtaining a lock for mtx_, but instead checking this atomic avoids
    /// that locking expense in the common case.
    std::atomic<size_t> pending_count_;
  };

  // --- construction and destruction ------------------------------------------

  endpoint(configuration config = {});

  endpoint(endpoint&&) = delete;
  endpoint(const endpoint&) = delete;
  endpoint& operator=(endpoint&&) = delete;
  endpoint& operator=(const endpoint&) = delete;

  /// Calls `shutdown`.
  ~endpoint();

  /// Shuts down all background activity and blocks until all local subscribers
  /// and publishers have terminated. *Must* be the very last function call on
  /// this object before destroying it.
  /// @warning *Destroys* the underlying actor system. Calling *any* member
  ///          function afterwards except `shutdown` and the destructor is
  ///          undefined behavior.
  void shutdown();

  /// @returns a unique node id for this endpoint.
  caf::node_id node_id() const;

  // --- peer management -------------------------------------------------------

  /// Listens at a specific port to accept remote peers.
  /// @param address The interface to listen at. If empty, listen on all
  ///                local interfaces.
  /// @param port The port to listen locally. If 0, the endpoint selects the
  ///             next available free port from the OS
  /// @returns The port the endpoint bound to or 0 on failure.
  uint16_t listen(const std::string& address = {}, uint16_t port = 0);

  /// Initiates a peering with a remote endpoint.
  /// @param address The IP address of the remote endpoint.
  /// @param port The TCP port of the remote endpoint.
  /// @param retry If non-zero, seconds after which to retry if connection
  ///        cannot be established, or breaks.
  /// @returns True if connection was successfulluy set up.
  /// @note The endpoint will also receive a status message indicating
  ///       success or failure.
  bool peer(const std::string& address, uint16_t port,
            timeout::seconds retry = timeout::seconds(10));

  /// Initiates a peering with a remote endpoint, without waiting
  /// for the operation to complete.
  /// @param address The IP address of the remote endpoint.
  /// @param port The TCP port of the remote endpoint.
  /// @param retry If non-zero, seconds after which to retry if connection
  ///        cannot be established, or breaks.
  /// @note The function returns immediately. The endpoint receives a status
  ///       message indicating the result of the peering operation.
  void peer_nosync(const std::string& address, uint16_t port,
            timeout::seconds retry = timeout::seconds(10));

  /// Shuts down a peering with a remote endpoint.
  /// @param address The IP address of the remote endpoint.
  /// @param port The TCP port of the remote endpoint.
  /// @returns True if connection was successfully torn down.
  /// @note The endpoint will also receive a status message
  ///       indicating sucess or failure.
  bool unpeer(const std::string& address, uint16_t port);

  /// Shuts down a peering with a remote endpoint, without waiting for
  /// for the operation to complete.
  /// @param address The IP address of the remote endpoint.
  /// @param port The TCP port of the remote endpoint.
  /// @returns True if connection was successfully torn down.
  /// @note The endpoint will also receive a status message
  ///       indicating sucess or failure.
  void unpeer_nosync(const std::string& address, uint16_t port);

  /// Retrieves a list of all known peers.
  /// @returns A pointer to the list
  std::vector<peer_info> peers() const;

  /// Retrieves a list of topics that peers have subscribed to on this endpoint.
  std::vector<topic> peer_subscriptions() const;

  // --- publishing ------------------------------------------------------------

  /// Publishes a message.
  /// @param t The topic of the message.
  /// @param d The message data.
  void publish(topic t, data d);

  /// Publishes a message to a specific peer endpoint only.
  /// @param dst The destination endpoint.
  /// @param t The topic of the message.
  /// @param d The message data.
  void publish(const endpoint_info& dst, topic t, data d);

  /// Publishes a message as vector.
  /// @param t The topic of the messages.
  /// @param xs The contents of the messages.
  void publish(topic t, std::initializer_list<data> xs);

  // Publishes the messages `x`.
  void publish(data_message x);

  // Publishes all messages in `xs`.
  void publish(std::vector<data_message> xs);

  publisher make_publisher(topic ts);

  /// Starts a background worker from the given set of functions that publishes
  /// a series of messages. The worker will run in the background, but `init`
  /// is guaranteed to be called before the function returns.
  template <class Init, class GetNext, class AtEnd>
  caf::actor publish_all(Init init, GetNext f, AtEnd pred) {
    std::mutex mx;
    std::condition_variable cv;
    auto res = make_actor([=,&mx,&cv](caf::event_based_actor* self) {
      self->make_source(
        core(),
        init,
        f,
        pred
      );
      std::unique_lock<std::mutex> guard{mx};
      cv.notify_one();
    });
    std::unique_lock<std::mutex> guard{mx};
    cv.wait(guard);
    return res;
  }

  /// Identical to ::publish_all, but does not guarantee that `init` is called
  /// before the function returns.
  template <class Init, class GetNext, class AtEnd>
  caf::actor publish_all_nosync(Init init, GetNext f, AtEnd pred) {
    return make_actor([=](caf::event_based_actor* self) {
      self->make_source(
        core(),
        init,
        f,
        pred
      );
    });
  }

  // --- subscribing events ----------------------------------------------------

  /// Returns a subscriber connected to this endpoint for receiving error and
  /// (optionally) status events.
  status_subscriber make_status_subscriber(bool receive_statuses = false);

  // --- forwarding events -----------------------------------------------------

  // Forward remote events for given topics even if no local subscriber.
  void forward(std::vector<topic> ts);

  // --- subscribing data ------------------------------------------------------

  /// Returns a subscriber connected to this endpoint for the topics `ts`.
  subscriber make_subscriber(std::vector<topic> ts, size_t max_qsize = 20u);

  /// Starts a background worker from the given set of function that consumes
  /// incoming messages. The worker will run in the background, but `init` is
  /// guaranteed to be called before the function returns.
  template <class Init, class HandleMessage, class Cleanup>
  caf::actor subscribe(std::vector<topic> topics, Init init, HandleMessage f,
                       Cleanup cleanup) {
    std::mutex mx;
    std::condition_variable cv;
    auto res = make_actor([=,&mx,&cv](caf::event_based_actor* self) {
      self->send(self * core(), atom::join::value, std::move(topics));
      self->become(
        [=](const stream_type& in) {
          self->make_sink(in, init, f, cleanup);
          self->unbecome();
        }
      );
      std::unique_lock<std::mutex> guard{mx};
      cv.notify_one();
    });
    std::unique_lock<std::mutex> guard{mx};
    cv.wait(guard);
    return res;
  }

  /// Identical to ::subscribe, but does not guarantee that `init` is called
  /// before the function returns.
  template <class Init, class HandleMessage, class Cleanup>
  caf::actor subscribe_nosync(std::vector<topic> topics, Init init,
                              HandleMessage f, Cleanup cleanup) {
    return make_actor([=](caf::event_based_actor* self) {
      self->send(self * core(), atom::join::value, std::move(topics));
      self->become(
        [=](const stream_type& in) {
          self->make_sink(in, init, f, cleanup);
          self->unbecome();
        }
      );
    });
  }

  // --- data stores -----------------------------------------------------------

  /// Attaches and/or creates a *master* data store with a globally unique name.
  /// @param name The name of the master.
  /// @param type The type of backend to use.
  /// @param opts The options controlling backend construction.
  /// @returns A handle to the frontend representing the master or an error if
  ///          a master with *name* exists already.
  expected<store> attach_master(std::string name, backend type,
                                backend_options opts=backend_options());


  /// Attaches and/or creates a *clone* data store to an existing master.
  /// @param name The name of the clone.
  /// @param resync_interval The frequency at which the clone will attempt to
  ///                        reconnect/resynchronize with its master in the
  ///                        event that it becomes disconnected (in seconds).
  /// @param stale_interval The amount of time (seconds) after which a clone
  ///                       that is disconnected from its master will start
  ///                       to treat its local cache as stale.  In the stale
  ///                       state, it responds to queries with an error.  A
  ///                       negative value here means the local cache never
  ///                       goes stale.
  /// @param mutation_buffer_interval The maximum amount of time (seconds)
  ///                                 that a disconnected clone will buffer
  ///                                 data store mutation commands.  If the
  ///                                 clone reconnects before this time, it
  ///                                 will replay all stored commands.  Note
  ///                                 that this doesn't completely prevent
  ///                                 the loss of store updates: all mutation
  ///                                 messages are fire-and-forget and not
  ///                                 explicitly acknowledged by the master.
  ///                                 A negative/zero value here indicates to
  ///                                 never buffer commands.
  /// @returns A handle to the frontend representing the clone, or an error if
  ///          a master *name* could not be found.
  expected<store> attach_clone(std::string name, double resync_interval=10.0,
                               double stale_interval=300.0,
                               double mutation_buffer_interval=120.0);

  // --- messaging -------------------------------------------------------------

  void send_later(caf::actor who, timespan after, caf::message msg) {
    clock_->send_later(std::move(who), after, std::move(msg));
  }

  // --- properties ------------------------------------------------------------

  /// Queries whether the endpoint waits for masters and slaves on shutdown.
  bool await_stores_on_shutdown() const {
    return await_stores_on_shutdown_;
  }

  /// Sets whether the endpoint waits for masters and slaves on shutdown.
  void await_stores_on_shutdown(bool x) {
    await_stores_on_shutdown_ = x;
  }

  bool is_shutdown() const {
    return destroyed_;
  }

  bool use_real_time() const {
    return clock_->real_time();
  }

  timestamp now() const {
    return clock_->now();
  }

  void advance_time(timestamp t) {
    clock_->advance_time(t);
  }

  caf::actor_system& system() {
    return system_;
  }

  const caf::actor& core() const {
    return core_;
  }

  const configuration& config() const {
    return config_;
  }

protected:
  caf::actor subscriber_;

private:
  caf::actor make_actor(actor_init_fun f);

  configuration config_;
  union {
    mutable caf::actor_system system_;
  };
  caf::actor core_;
  bool await_stores_on_shutdown_;
  std::vector<caf::actor> children_;
  bool destroyed_;
  clock* clock_;
};

} // namespace broker
