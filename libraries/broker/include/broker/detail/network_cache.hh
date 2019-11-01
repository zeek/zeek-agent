#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

#include <caf/actor.hpp>
#include <caf/event_based_actor.hpp>
#include <caf/io/middleman.hpp>
#include <caf/openssl/manager.hpp>
#include <caf/optional.hpp>
#include <caf/result.hpp>

#include "broker/logger.hh"
#include "broker/network_info.hh"

namespace broker {
namespace detail {

/// Maps any number of network addresses to remote actor handles. Actors can be
/// reachable under several addresses for multiple reasons. For example,
/// "127.0.0.1" and "localhost" point to the same network endpoint or an actor
/// can get published to more than one port.
class network_cache {
public:
  network_cache(caf::event_based_actor* selfptr);

  void set_use_ssl(bool use_ssl_) { use_ssl = use_ssl_; }

  /// Either returns an actor handle immediately if the entry is cached or
  /// queries the middleman actor and responds later via response promise.
  caf::result<caf::actor> fetch(const network_info& x);

  template <class OnResult, class OnError>
  void fetch(const network_info& x, OnResult f, OnError g) {
    using namespace caf;
    auto y = find(x);
    if (y) {
      f(*y);
      return;
    }
    BROKER_INFO("initiating connection to"
                << (x.address + ":" + std::to_string(x.port))
                << (use_ssl ? "(SSL)" : "(no SSL)"));
    auto hdl = (use_ssl ? self->home_system().openssl_manager().actor_handle()
                        : self->home_system().middleman().actor_handle());
    self->request(hdl, infinite,
                  connect_atom::value, x.address, x.port)
    .then(
      [=](const node_id&, strong_actor_ptr& res,
          std::set<std::string>& ifs) mutable {
        if (!ifs.empty())
          g(sec::unexpected_actor_messaging_interface);
        else if (res == nullptr)
          g(sec::no_actor_published_at_port);
        else {
          auto res_hdl = actor_cast<actor>(std::move(res));
          hdls_.emplace(x, res_hdl);
          addrs_.emplace(res_hdl, x);
          f(std::move(res_hdl));
        }
      },
      [=](error& err) mutable {
        g(std::move(err));
      }
    );
  }

  template <class OnResult, class OnError>
  void fetch(const caf::actor& x, OnResult f, OnError g) {
    using namespace caf;
    auto y = find(x);
    if (y) {
      f(*y);
      return;
    }
    BROKER_INFO("retrieving connection for"
                << x << (use_ssl ? "(SSL)" : "(no SSL)"));
    auto hdl = (use_ssl ? self->home_system().openssl_manager().actor_handle()
                        : self->home_system().middleman().actor_handle());
    self->request(hdl, infinite,
                  get_atom::value, x.node())
    .then(
      [=](const node_id&, std::string& address, uint16_t port) mutable {
        network_info result{std::move(address), port};
        hdls_.emplace(result, x);
        addrs_.emplace(x, result);
        f(std::move(result));
      },
      [=](error& err) mutable {
        g(std::move(err));
      }
    );
  }

  /// Returns the handle associated to `x`, if any.
  caf::optional<caf::actor> find(const network_info& x);

  /// Returns all known network addresses for `x`.
  caf::optional<network_info> find(const caf::actor& x);

  /// Maps `x` to `y` and vice versa.
  void add(const caf::actor& x, const network_info& y);

  /// Removes mapping for `x` and the corresponding network_info.
  void remove(const caf::actor& x);

  /// Removes mapping for `x` and the corresponding actor handle.
  void remove(const network_info& x);

private:
  // Parent.
  caf::event_based_actor* self;
  bool use_ssl = true;

  // Maps remote actor handles to network addresses.
  std::unordered_map<caf::actor, network_info> addrs_;

  // Maps network addresses to remote actor handles.
  std::unordered_map<network_info, caf::actor> hdls_;
};

} // namespace detail
} // namespace broker
