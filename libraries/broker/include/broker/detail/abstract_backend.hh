#pragma once

#include "broker/data.hh"
#include "broker/expected.hh"
#include "broker/optional.hh"
#include "broker/snapshot.hh"

#include <deque>

namespace broker {
namespace detail {

using expirable = std::pair<broker::data, timestamp>;
using expirables = std::deque<expirable>;

/// Abstract base class for a key-value storage backend.
class abstract_backend {
public:
  abstract_backend() = default;

  virtual ~abstract_backend() = default;

  // --- modifiers ------------------------------------------------------------

  /// Inserts or updates a key-value pair.
  /// @param key The key to update/insert.
  /// @param value The value associated with *key*.
  /// @param expiry An optional expiration time for the entry.
  /// @returns `nil` on success.
  virtual expected<void> put(const data& key, data value,
                             optional<timestamp> expiry = {}) = 0;

  /// Adds one value to another value.
  /// @param key The key associated with the existing value to add to.
  /// @param value The value to add on top of the existing value at *key*.
  /// @param init_type The type of data to initialize when the key doesn't exist.
  /// @param t The point in time this modification took place.
  /// @returns `nil` on success.
  virtual expected<void> add(const data& key, const data& value,
                             data::type init_type,
                             optional<timestamp> expiry = {});

  /// Removes one value from another value.
  /// @param key The key associated with the existing value to subtract from.
  /// @param value The value to subtract from the existing value at *key*.
  /// @param t The point in time this modification took place.
  /// @returns `nil` on success.
  virtual expected<void> subtract(const data& key, const data& value,
                                  optional<timestamp> expiry = {});

  /// Removes a key and its associated value from the store, if it exists.
  /// @param key The key to use.
  /// @returns `nil` if *key* was removed successfully or if *key* did not
  /// exist.
  virtual expected<void> erase(const data& key) = 0;

  /// Empties out the store.
  /// @returns `nil` if the store was successfully emptied out.
  virtual expected<void> clear() = 0;

  /// Removes a key and its associated value from the store, if it exists and
  /// has an expiration in the past.
  /// @param key The key to expire.
  /// @param current_time The time used to compare whether to actual
  /// expire the given key.
  /// @returns `true` if *key* was expired (and deleted) successfully, and
  /// `false` if the value cannot be expired yet, i.e., the existing expiry
  /// time lies in the future.
  virtual expected<bool> expire(const data& key,
                                timestamp current_time) = 0;

  // --- inspectors -----------------------------------------------------------

  /// Retrieves the value associated with a given key.
  /// @param key The key to use.
  /// @returns The value associated with *key*.
  virtual expected<data> get(const data& key) const = 0;

  /// Retrieves a specific aspect of a value for a given key.
  /// @param key The key to use.
  /// @param aspect The aspect of the value at *key* to lookup.
  /// @returns The *aspect* of the value at *key*.
  virtual expected<data> get(const data& key, const data& value) const;

  /// Checks if a key exists.
  /// @param key The key to check.
  /// @returns `true` if the *key* exists and `false` if it doesn't.
  /// the query.
  virtual expected<bool> exists(const data& key) const = 0;

  /// Retrieves the number of entries in the store.
  /// @returns The number of key-value pairs in the store.
  virtual expected<uint64_t> size() const = 0;

  /// Retrieves the current keys.
  /// @returns The set of current keys.
  virtual expected<data> keys() const = 0;

  /// Retrieves all key-value pairs.
  /// @returns A snapshot of the store that includes its content.
  virtual expected<broker::snapshot> snapshot() const = 0;

  /// @returns the set of all keys that have expiry times.
  virtual expected<expirables> expiries() const = 0;
};

} // namespace detail
} // namespace broker
