#pragma once

#include <string>
#include <vector>

#include <caf/actor.hpp>
#include <caf/cow_tuple.hpp>
#include <caf/error.hpp>
#include <caf/make_message.hpp>
#include <caf/scoped_actor.hpp>
#include <caf/stream.hpp>

#include "broker/api_flags.hh"
#include "broker/atoms.hh"
#include "broker/data.hh"
#include "broker/fwd.hh"
#include "broker/mailbox.hh"
#include "broker/message.hh"
#include "broker/optional.hh"
#include "broker/error.hh"
#include "broker/expected.hh"
#include "broker/status.hh"
#include "broker/timeout.hh"

namespace broker {

class endpoint;

/// A key-value store (either a *master* or *clone*) that supports modifying
/// and querying contents.
class store {
public:
  friend class endpoint;

  using stream_type = caf::stream<command_message>;

  /// A response to a lookup request issued by a ::proxy.
  struct response {
    expected<data> answer;
    request_id id;
  };

  /// A utility to decouple store request from response processing.
  class proxy {
  public:
    proxy() = default;

    /// Constructs a proxy for a given store.
    /// @param s The store to create a proxy for.
    explicit proxy(store& s);

    /// Performs a request to check existance of a value.
    /// @returns A unique identifier for this request to correlate it with a
    /// response.
    request_id exists(data key);

    /// Performs a request to retrieve a value.
    /// @param key The key of the value to retrieve.
    /// @returns A unique identifier for this request to correlate it with a
    /// response.
    request_id get(data key);

    /// Inserts a value if the key does not already exist.
    /// @param key The key of the key-value pair.
    /// @param value The value of the key-value pair.
    /// @param expiry An optional expiration time for *key*.
    /// @returns A unique identifier for this request to correlate it with a
    /// response.
    request_id put_unique(data key, data value,
                          optional<timespan> expiry = {});

    /// For containers values, retrieves a specific index from the value. This
    /// is supported for sets, tables, and vectors.
    /// @param key The key of the container value to retrieve from.
    /// @param key The index of the value to retrieve.
    /// @returns A unique identifier for this request to correlate it with a
    /// response.
    request_id get_index_from_value(data key, data index);

    /// Performs a request to retrieve a store's keys.
    /// @returns A unique identifier for this request to correlate it with a
    /// response.
    request_id keys();

    /// Retrieves the proxy's mailbox that reflects query responses.
    broker::mailbox mailbox();

    /// Consumes the next response or blocks until one arrives.
    /// @returns The next response in the proxy's mailbox.
    response receive();

    /// Consumes the next N responses or blocks until N responses arrive.
    /// @returns The next N responses in the proxy's mailbox.
    std::vector<response> receive(size_t n);

  private:
    request_id id_ = 0;
    caf::actor frontend_;
    caf::actor proxy_;
  };

  /// Default-constructs an uninitialized store.
  store() = default;

  // --- inspectors -----------------------------------------------------------

  /// Retrieves the name of the store.
  /// @returns The store name.
  const std::string& name() const;

  /// Checks whether a key exists in the store.
  /// @returns A boolean that's if the key exists.
  expected<data> exists(data key) const;

  /// Retrieves a value.
  /// @param key The key of the value to retrieve.
  /// @returns The value under *key* or an error.
  expected<data> get(data key) const;

  /// Inserts a value if the key does not already exist.
  /// @param key The key of the key-value pair.
  /// @param value The value of the key-value pair.
  /// @param expiry An optional expiration time for *key*.
  /// @returns A true data value if inserted or false if key already existed.
  expected<data> put_unique(data key, data value,
                            optional<timespan> expiry = {}) const;

  /// For containers values, retrieves a specific index from the value. This
  /// is supported for sets, tables, and vectors.
  /// @param key The key of the value to retrieve the index from.
  /// @param index The index of the value to retrieve.
  /// @returns For tables and vector, the value under *index* or an error.
  /// For sets, a boolean indicating whether the set contains the index.
  /// Always returns an error if the store does not have the key.
  expected<data> get_index_from_value(data key, data index) const;

  /// Retrieves a copy of the store's current keys, returned as a set.
  expected<data> keys() const;

  /// Retrieves the frontend.
  inline const caf::actor& frontend() const {
    return frontend_;
  }

  // --- modifiers -----------------------------------------------------------

  /// Inserts or updates a value.
  /// @param key The key of the key-value pair.
  /// @param value The value of the key-value pair.
  /// @param expiry An optional expiration time for *key*.
  void put(data key, data value, optional<timespan> expiry = {}) const;

  /// Removes the value associated with a given key.
  /// @param key The key to remove from the store.
  void erase(data key) const;

  /// Empties out the store.
  void clear() const;

  /// Increments a value by a given amount. This is supported for all
  /// numerical types as well as for timestamps.
  /// @param key The key of the value to increment.
  /// @param value The amount to increment the value.
  /// @param expiry An optional new expiration time for *key*.
  void increment(data key, data amount, optional<timespan> expiry = {}) const {
    auto init_type = data::type::none;

    switch ( amount.get_type() ) {
      case data::type::count:
        init_type = data::type::count;
        break;
      case data::type::integer:
        init_type = data::type::integer;
        break;
      case data::type::real:
        init_type = data::type::real;
        break;
      case data::type::timespan:
        init_type = data::type::timestamp;
        break;
      default:
        break;
    }

    add(key, amount, init_type, expiry);
  }

  /// Decrements a value by a given amount. This is supported for all
  /// numerical types as well as for timestamps.
  /// @param key The key of the value to increment.
  /// @param value The amount to decrement the value.
  /// @param expiry An optional new expiration time for *key*.
  void decrement(data key, data amount, optional<timespan> expiry = {}) const {
    subtract(key, amount, expiry);
  }

  /// Appends a string to another one.
  /// @param key The key of the string to which to append.
  /// @param str The string to append.
  /// @param expiry An optional new expiration time for *key*.
  void append(data key, data str, optional<timespan> expiry = {}) const {
    add(key, str, data::type::string, expiry);
  }

  /// Inserts an index into a set.
  /// @param key The key of the set into which to insert the value.
  /// @param index The index to insert.
  /// @param expiry An optional new expiration time for *key*.
  void insert_into(data key, data index, optional<timespan> expiry = {}) const {
      add(key, index, data::type::set, expiry);
  }

  /// Inserts an index into a table.
  /// @param key The key of the table into which to insert the value.
  /// @param index The index to insert.
  /// @param value The value to associated with the inserted index. For sets, this is ignored.
  /// @param expiry An optional new expiration time for *key*.
  void insert_into(data key, data index, data value, optional<timespan> expiry = {}) const {
      add(key, vector({index, value}), data::type::table, expiry);
  }

  /// Removes am index from a set or table.
  /// @param key The key of the set/table from which to remove the value.
  /// @param index The index to remove.
  /// @param expiry An optional new expiration time for *key*.
  void remove_from(data key, data index, optional<timespan> expiry = {}) const {
    subtract(key, index, expiry);
  }

  /// Appends a value to a vector.
  /// @param key The key of the vector to which to append the value.
  /// @param value The value to append.
  /// @param expiry An optional new expiration time for *key*.
  void push(data key, data value, optional<timespan> expiry = {}) const {
    add(key, value, data::type::vector, expiry);
  }

  /// Removes the last value of a vector.
  /// @param key The key of the vector from which to remove the last value.
  /// @param expiry An optional new expiration time for *key*.
  void pop(data key, optional<timespan> expiry = {}) const {
    subtract(key, key, expiry);
  }

private:
  store(caf::actor actor, std::string name);

  /// Adds a value to another one, with a type-specific meaning of
  /// "add". This is the backend for a number of the modifiers methods.
  /// @param key The key of the key-value pair.
  /// @param value The value of the key-value pair.
  /// @param init_type The type of data to initialize when the key does not exist.
  /// @param expiry An optional new expiration time for *key*.
  void add(data key, data value, data::type init_type, optional<timespan> expiry = {}) const;

  /// Subtracts a value from another one, with a type-specific meaning of
  /// "substract". This is the backend for a number of the modifiers methods.
  /// @param key The key of the key-value pair.
  /// @param value The value of the key-value pair.
  /// @param expiry An optional new expiration time for *key*.
  void subtract(data key, data value, optional<timespan> expiry = {}) const;

  template <class T, class... Ts>
  expected<T> request(Ts&&... xs) const {
    if (!frontend_)
      return make_error(ec::unspecified, "store not initialized");
    expected<T> res{ec::unspecified};
    caf::scoped_actor self{frontend_->home_system()};
    auto msg = caf::make_message(std::forward<Ts>(xs)...);
    self->request(frontend_, timeout::frontend, std::move(msg)).receive(
      [&](T& x) {
        res = std::move(x);
      },
      [&](caf::error& e) {
        res = std::move(e);
      }
    );
    return res;
  }

  caf::actor frontend_;
  std::string name_;
};

} // namespace broker
