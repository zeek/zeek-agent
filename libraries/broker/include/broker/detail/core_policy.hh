#pragma once

#include <vector>
#include <utility>
#include <unordered_set>
#include <unordered_map>

#include <caf/actor.hpp>
#include <caf/actor_addr.hpp>
#include <caf/broadcast_downstream_manager.hpp>
#include <caf/cow_tuple.hpp>
#include <caf/detail/stream_distribution_tree.hpp>
#include <caf/fused_downstream_manager.hpp>
#include <caf/fwd.hpp>
#include <caf/message.hpp>
#include <caf/stream_slot.hpp>

#include "broker/data.hh"
#include "broker/detail/assert.hh"
#include "broker/detail/generator_file_writer.hh"
#include "broker/filter_type.hh"
#include "broker/internal_command.hh"
#include "broker/logger.hh"
#include "broker/message.hh"
#include "broker/peer_filter.hh"
#include "broker/topic.hh"

namespace broker {

struct core_state;

namespace detail {

/// Sets up a configurable stream manager to act as a distribution tree for
/// Broker.
class core_policy {
public:
  // -- member types -----------------------------------------------------------

  /// Type to store a TTL for messages forwarded to peers.
  using ttl = uint16_t;

  /// Helper trait for defining streaming-related types for local actors
  /// (workers and stores).
  template <class T>
  struct local_trait {
    /// Type of a single element in the stream.
    using element = caf::cow_tuple<topic, T>;

    /// Type of a full batch in the stream.
    using batch = std::vector<element>;

    /// Type of the downstream_manager that broadcasts data to local actors.
    using manager = caf::broadcast_downstream_manager<element, filter_type,
                                                      prefix_matcher>;
  };

  /// Streaming-related types for workers.
  using worker_trait = local_trait<data>;

  /// Streaming-related types for stores.
  using store_trait = local_trait<internal_command>;

  /// Streaming-related types for peers.
  struct peer_trait {
    /// Type of a single element in the stream.
    using element = node_message;

    using batch = std::vector<element>;

    /// Type of the downstream_manager that broadcasts data to local actors.
    using manager = caf::broadcast_downstream_manager<element, peer_filter,
                                                      peer_filter_matcher>;
  };

  /// Maps actor handles to path IDs.
  using peer_to_path_map = std::map<caf::actor, caf::stream_slot>;

  /// Maps path IDs to actor handles.
  using path_to_peer_map = std::map<caf::stream_slot, caf::actor>;

  /// Composed downstream_manager type for bundled dispatching.
  using downstream_manager_type
    = caf::fused_downstream_manager<peer_trait::manager, worker_trait::manager,
                                    store_trait::manager>;

  /// Stream handshake in step 1 that includes our own filter. The receiver
  /// replies with a step2 handshake.
  using step1_handshake = caf::outbound_stream_slot<node_message,
                                                    filter_type,
                                                    caf::actor>;

  /// Stream handshake in step 2. The receiver already has our filter
  /// installed.
  using step2_handshake = caf::outbound_stream_slot<node_message,
                                                    caf::atom_value,
                                                    caf::actor>;

  core_policy(caf::detail::stream_distribution_tree<core_policy>* parent,
              core_state* state, filter_type filter);

  bool substream_local_data() const;

  void before_handle_batch(caf::stream_slot slot,
                           const caf::strong_actor_ptr& hdl);

  void handle_batch(caf::stream_slot slot, const caf::strong_actor_ptr& hdl,
                    caf::message& xs);

  void after_handle_batch(caf::stream_slot slot,
                          const caf::strong_actor_ptr& hdl);

  void ack_open_success(caf::stream_slot slot,
                        const caf::actor_addr& rebind_from,
                        caf::strong_actor_ptr rebind_to);

  void ack_open_failure(caf::stream_slot slot,
                        const caf::actor_addr& rebind_from,
                        caf::strong_actor_ptr rebind_to);

  void push_to_substreams(std::vector<caf::message> vec);

  // -- status updates to the state --------------------------------------------

  void peer_lost(const caf::actor& hdl);

  void peer_removed(const caf::actor& hdl);

  // -- callbacks for close/drop events ----------------------------------------

  /// Output path gracefully closes.
  void path_closed(caf::stream_slot slot);

  /// Output path fails with an error.
  void path_force_closed(caf::stream_slot slot, caf::error reason);

  /// Input path gracefully closes.
  void path_dropped(caf::stream_slot slot);

  /// Input path fails with an error.
  void path_force_dropped(caf::stream_slot slot, caf::error reason);

  // -- state required by the distribution tree --------------------------------

  bool shutting_down() const;

  void shutting_down(bool value);

  // -- peer management --------------------------------------------------------

  /// Queries whether `hdl` is a known peer.
  bool has_peer(const caf::actor& hdl) const;

  /// Block peer messages from being handled.  They are buffered until unblocked.
  void block_peer(caf::actor peer);

  /// Unblock peer messages and flush any buffered messages immediately.
  void unblock_peer(caf::actor peer);

  /// Starts the handshake process for a new peering (step #1 in core_actor.cc).
  /// @returns `false` if the peer is already connected, `true` otherwise.
  /// @param peer_hdl Handle to the peering (remote) core actor.
  /// @param peer_filter Filter of our peer.
  /// @param send_own_filter Sends a `(filter, self)` handshake if `true`,
  ///                        `('ok', self)` otherwise.
  /// @pre `current_sender() != nullptr`
  template <bool SendOwnFilter>
  typename std::conditional<
    SendOwnFilter,
    step1_handshake,
    step2_handshake
  >::type
  start_peering(const caf::actor& peer_hdl, filter_type peer_filter) {
    BROKER_TRACE(BROKER_ARG(peer_hdl) << BROKER_ARG(peer_filter));
    // Token for static dispatch of add().
    std::integral_constant<bool, SendOwnFilter> send_own_filter_token;
    // Check whether we already send outbound traffic to the peer. Could use
    // `CAF_ASSERT` instead, because this must'nt get called for known peers.
    if (peer_to_opath_.count(peer_hdl) != 0) {
      BROKER_ERROR("peer already connected");
      return {};
    }
    // Add outbound path to the peer.
    auto slot = add(send_own_filter_token, peer_hdl);
    // Make sure the peer receives the correct traffic.
    out().assign<peer_trait::manager>(slot);
    peers().set_filter(slot,
                       std::make_pair(peer_hdl.address(),
                                      std::move(peer_filter)));
    // Add bookkeeping state for our new peer.
    add_opath(slot, peer_hdl);
    return slot;
  }

  /// Acknowledges an incoming peering request (step #2/3 in core_actor.cc).
  /// @param peer_hdl Handle to the peering (remote) core actor.
  /// @returns `false` if the peer is already connected, `true` otherwise.
  /// @pre Current message is an `open_stream_msg`.
  void ack_peering(const caf::stream<node_message>& in,
                   const caf::actor& peer_hdl);

  /// Queries whether we have an outbound path to `hdl`.
  bool has_outbound_path_to(const caf::actor& peer_hdl);

  /// Queries whether we have an inbound path from `hdl`.
  bool has_inbound_path_from(const caf::actor& peer_hdl);

  /// Removes a peer, aborting any stream to and from that peer.
  bool remove_peer(const caf::actor& hdl, caf::error reason, bool silent,
                   bool graceful_removal);

  /// Updates the filter of an existing peer.
  bool update_peer(const caf::actor& hdl, filter_type filter);

  // -- management of worker and storage streams -------------------------------

  /// Adds the sender of the current message as worker by starting an output
  /// stream to it.
  /// @pre `current_sender() != nullptr`
  caf::outbound_stream_slot<worker_trait::element>
  add_worker(filter_type filter);

  // -- selectively pushing data into the streams ------------------------------

  /// Pushes data to workers without forwarding it to peers.
  void local_push(data_message x);

  /// Pushes data to stores without forwarding it to peers.
  void local_push(command_message x);

  /// Pushes data to peers only without forwarding it to local substreams.
  void remote_push(node_message x);

  /// Pushes data to peers and workers.
  void push(data_message msg);

  /// Pushes data to peers and stores.
  void push(command_message msg);

  // -- properties -------------------------------------------------------------

  /// Returns the fused downstream_manager of the parent.
  downstream_manager_type& out() noexcept;

  /// Returns the fused downstream_manager of the parent.
  const downstream_manager_type& out() const noexcept;

  /// Returns the downstream_manager for peer traffic.
  peer_trait::manager& peers() noexcept;

  /// Returns the downstream_manager for peer traffic.
  const peer_trait::manager& peers() const noexcept;

  /// Returns the downstream_manager for worker traffic.
  worker_trait::manager& workers() noexcept;

  /// Returns the downstream_manager for worker traffic.
  const worker_trait::manager& workers() const noexcept;

  /// Returns the downstream_manager for store traffic.
  store_trait::manager& stores() noexcept;

  /// Returns the downstream_manager for store traffic.
  const store_trait::manager& stores() const noexcept;

  /// Returns a pointer to the owning actor.
  caf::scheduled_actor* self();

  /// Returns a pointer to the owning actor.
  const caf::scheduled_actor* self() const;

  /// Applies `f` to each peer.
  template <class F>
  void for_each_peer(F f) {
    // visit all peers that have at least one path still connected
    auto peers = get_peer_handles();
    std::for_each(peers.begin(), peers.end(), std::move(f));
  }

  /// Returns all known peers.
  std::vector<caf::actor> get_peer_handles();

  /// Finds the first peer handle that satisfies the predicate.
  template <class Predicate>
  caf::actor find_output_peer_hdl(Predicate pred) {
    for (auto& kvp : peer_to_opath_)
      if (pred(kvp.first))
        return kvp.first;
    return nullptr;
  }

  /// Applies `f` to each filter.
  template <class F>
  void for_each_filter(F f) {
    for (auto& kvp : peers().states()) {
      f(kvp.second.filter);
    }
  }

private:
  /// @pre `recorder_ != nullptr`
  template <class T>
  bool try_record(const T& x) {
    BROKER_ASSERT(recorder_ != nullptr);
    BROKER_ASSERT(remaining_records_ > 0);
    if (auto err = recorder_->write(x)) {
      BROKER_WARNING("unable to write to generator file:" << err);
      recorder_ = nullptr;
      remaining_records_ = 0;
      return false;
    }
    if (--remaining_records_ == 0) {
      BROKER_DEBUG("reached recording cap, close file");
      recorder_ = nullptr;
    }
    return true;
  }

  bool try_record(const node_message& x) {
    return try_record(x.content);
  }

  template <class T>
  bool try_handle(caf::message& msg, const char* debug_msg) {
    CAF_IGNORE_UNUSED(debug_msg);
    if (msg.match_elements<T>()) {
      using iterator_type = typename T::iterator;
      auto ttl0 = initial_ttl();
      auto push_unrecorded = [&](iterator_type first, iterator_type last) {
        for (auto i = first; i != last; ++i)
          peers().push(make_node_message(std::move(*i), ttl0));
      };
      auto push_recorded = [&](iterator_type first, iterator_type last) {
        for (auto i = first; i != last; ++i) {
          if (!try_record(*i))
            return i;
          peers().push(make_node_message(std::move(*i), ttl0));
        }
        return last;
      };
      BROKER_DEBUG(debug_msg);
      auto& xs = msg.get_mutable_as<T>(0);
      if (recorder_ == nullptr) {
        push_unrecorded(xs.begin(), xs.end());
      } else {
        auto n = std::min(remaining_records_, xs.size());
        auto first = xs.begin();
        auto last = xs.end();
        auto i = push_recorded(first, first + n);
        if (i != last)
          push_unrecorded(i, last);
      }
      return true;
    }
    return false;
  }

  /// Returns the initial TTL value when publishing data.
  ttl initial_ttl() const;

  /// Adds entries to `peer_to_ipath_` and `ipath_to_peer_`.
  void add_ipath(caf::stream_slot slot, const caf::actor& peer_hdl);

  /// Adds entries to `peer_to_opath_` and `opath_to_peer_`.
  void add_opath(caf::stream_slot slot, const caf::actor& peer_hdl);

  /// Path `slot` in `xs` was dropped or closed. Removes the entry in `xs` as
  /// well as the associated entry in `ys`. Also removes the entries from `as`
  /// and `bs` if `reason` is not default constructed. Calls `remove_peer` if
  /// no entry for a peer exists afterwards.
  void remove_cb(caf::stream_slot slot, path_to_peer_map& xs,
                 peer_to_path_map& ys, peer_to_path_map& zs, caf::error reason);

  /// Sends a handshake with filter in step #1.
  step1_handshake add(std::true_type send_own_filter, const caf::actor& hdl);

  /// Sends a handshake with 'ok' in step #2.
  step2_handshake add(std::false_type send_own_filter, const caf::actor& hdl);

  /// Pointer to the parent.
  caf::detail::stream_distribution_tree<core_policy>* parent_;

  /// Pointer to the state.
  core_state* state_;

  /// Maps peer handles to output path IDs.
  peer_to_path_map peer_to_opath_;

  /// Maps output path IDs to peer handles.
  path_to_peer_map opath_to_peer_;

  /// Maps peer handles to input path IDs.
  peer_to_path_map peer_to_ipath_;

  /// Maps input path IDs to peer handles.
  path_to_peer_map ipath_to_peer_;

  /// Peers that are currently blocked (messages buffered until unblocked).
  std::unordered_set<caf::actor> blocked_peers;

  /// Messages that are currently buffered.
  std::unordered_map<caf::actor, std::vector<caf::message>> blocked_msgs;

  /// Helper for recording meta data of published messages.
  detail::generator_file_writer_ptr recorder_;

  /// Counts down when using a `recorder_` to cap maximum file entries.
  size_t remaining_records_;
};

} // namespace detail
} // namespace broker
