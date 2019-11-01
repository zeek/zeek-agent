#pragma once

#include <cstdint>
#include <deque>
#include <unordered_map>
#include <unordered_set>

#include <caf/actor.hpp>
#include <caf/actor_addr.hpp>

#include "broker/topic.hh"
#include "broker/optional.hh"

#include "broker/detail/radix_tree.hh"

namespace broker {
namespace detail {

using actor_set = std::unordered_set<caf::actor>;
using topic_set = radix_tree<bool>;

/// An actor with the associated topics in which it claims interest.
class subscriber {
public:
   /// Default constructor.
  subscriber() = default;

   /// Construct from given actor and topic set.
  subscriber(caf::actor a, topic_set ts)
    : who(std::move(a)), subscriptions(std::move(ts)) {
  }

  caf::actor who = caf::invalid_actor;
  topic_set subscriptions;
};

/// Manages a collection of subscribers and their subscriptions.
class subscription_registry {
public:
  /// Insert subscriber into container, overwriting any existing data
  /// associated with the subscriber's actor.
  /// @return false if it had to overwrite existing data.
  bool insert(subscriber s);

  /// Remove a subscriber from the container and return it if it exists.
  /// @param a the actor address associated with the subscriber.
  /// @return the associated subscriber if it was in the container.
  optional<subscriber> erase(const caf::actor_addr& a);

  /// Register a subscription topic to a subscriber.
  /// @param t the topic of the subscription to register.
  /// @param a the actor associated with the subscriber.
  /// @return false if the subscriber was already registered for the topic.
  bool register_topic(topic t, caf::actor a);

  /// Unregister a topic from a subscriber.
  /// @param t a topic to unregister.
  /// @param a the actor address associated with the subscriber.
  /// @return false if an associated subscriber doesn't exist.
  bool unregister_topic(const topic& t, const caf::actor_addr a);

  /// @return All actors that have registered subscriptions with topic names
  /// that are a prefix of the given topic name.  Note that an actor may
  /// appear more than once if they registered multiple subscriptions that
  /// match the given topic name.
  std::deque<radix_tree<actor_set>::iterator>
  prefix_matches(const topic& t) const;

  /// @return All actors that have registered subscriptions with topic names
  /// that are a prefix of the given topic name.
  actor_set unique_prefix_matches(const topic& t) const;

  /// @return All actors that have registered subscriptions with topic names
  /// exactly matching the given topic name.
  const actor_set* exact_match(const topic& t) const;

  /// @return All subscription topics currently registered.
  const topic_set& topics() const {
    return all_topics;
  }

  /// @return true if a subscriber associated with the actor address is
  /// registered.
  bool have_subscriber(const caf::actor_addr& a) const {
    return subs_by_actor.find(a) != subs_by_actor.end();
  }

  /// @return true if a subscriber is registered for the exact topic argument.
  bool have_subscriber_for(const topic& t) const {
    return static_cast<bool>(exact_match(t));
  }

private:
  radix_tree<actor_set> subs_by_topic;
  std::unordered_map<caf::actor_addr, subscriber> subs_by_actor;
  topic_set all_topics;
};

} // namespace detail
} // namespace broker
