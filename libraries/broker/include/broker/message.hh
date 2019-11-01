#pragma once

#include <cstdint>

#include <caf/cow_tuple.hpp>
#include <caf/variant.hpp>

#include "broker/data.hh"
#include "broker/internal_command.hh"
#include "broker/topic.hh"

namespace broker {

/// A user-defined message with topic and data.
using data_message = caf::cow_tuple<topic, data>;

/// A broker-internal message with topic and command.
using command_message = caf::cow_tuple<topic, internal_command>;

/// A message for node-to-node communication with either a user-defined data
/// message or a broker-internal command messages.
struct node_message {
  /// Content type of the message.
  using value_type = caf::variant<data_message, command_message>;

  /// Content of the message.
  value_type content;

  /// Time-to-life counter.
  uint16_t ttl;
};

/// Returns whether `x` contains a ::node_message.
inline bool is_data_message(const node_message::value_type& x) {
  return caf::holds_alternative<data_message>(x);
}

/// Returns whether `x` contains a ::node_message.
inline bool is_data_message(const node_message& x) {
  return is_data_message(x.content);
}

/// Returns whether `x` contains a ::command_message.
inline bool is_command_message(const node_message::value_type& x) {
  return caf::holds_alternative<command_message>(x);
}

/// Returns whether `x` contains a ::command_message.
inline bool is_command_message(const node_message& x) {
  return is_command_message(x.content);
}

/// @relates node_message
template <class Inspector>
typename Inspector::result_type inspect(Inspector& f, node_message& x) {
  return f(x.content, x.ttl);
}

/// Generates a broker ::data_message.
template <class Topic, class Data>
data_message make_data_message(Topic&& t, Data&& d) {
  return data_message(std::forward<Topic>(t), std::forward<Data>(d));
}

/// Generates a broker ::command_message.
template <class Topic, class Command>
command_message make_command_message(Topic&& t, Command&& d) {
  return command_message(std::forward<Topic>(t), std::forward<Command>(d));
}

/// Generates a broker ::node_message.
inline node_message make_node_message(data_message msg, uint16_t ttl) {
  return {std::move(msg), ttl};
}

/// Generates a broker ::node_message.
inline node_message make_node_message(command_message msg, uint16_t ttl) {
  return {std::move(msg), ttl};
}

/// Generates a broker ::node_message.
inline node_message make_node_message(node_message::value_type msg,
                                      uint16_t ttl) {
  return {std::move(msg), ttl};
}

/// Retrieves the topic from a ::data_message.
inline const topic& get_topic(const data_message& x) {
  return get<0>(x);
}

/// Retrieves the topic from a ::command_message.
inline const topic& get_topic(const command_message& x) {
  return get<0>(x);
}

/// Retrieves the topic from a ::generic_message.
inline const topic& get_topic(const node_message::value_type& x) {
  if (is_data_message(x))
    return get_topic(caf::get<data_message>(x));
  return get_topic(caf::get<command_message>(x));
}

/// Retrieves the topic from a ::generic_message.
inline const topic& get_topic(const node_message& x) {
  return get_topic(x.content);
}

/// Moves the topic out of a ::data_message. Causes `x` to make a lazy copy of
/// its content if other ::data_message objects hold references to it.
inline topic&& move_topic(data_message& x) {
  return std::move(get<0>(x.unshared()));
}

/// Moves the topic out of a ::command_message. Causes `x` to make a lazy copy
/// of its content if other ::command_message objects hold references to it.
inline topic&& move_topic(command_message& x) {
  return std::move(get<0>(x.unshared()));
}

/// Moves the topic out of a ::node_message. Causes `x` to make a lazy copy of
/// its content if other ::node_message objects hold references to it.
inline topic&& move_topic(node_message::value_type& x) {
  if (is_data_message(x))
    return move_topic(caf::get<data_message>(x));
  return move_topic(caf::get<command_message>(x));
}

/// Moves the topic out of a ::node_message. Causes `x` to make a lazy copy of
/// its content if other ::node_message objects hold references to it.
inline topic&& move_topic(node_message& x) {
  return move_topic(x.content);
}


/// Retrieves the data from a ::data_message.
inline const data& get_data(const data_message& x) {
  return get<1>(x);
}

/// Moves the data out of a ::data_message. Causes `x` to make a lazy copy of
/// its content if other ::data_message objects hold references to it.
inline data&& move_data(data_message& x) {
  return std::move(get<1>(x.unshared()));
}

/// Retrieves the command content from a ::command_message.
inline const internal_command::variant_type&
get_command(const command_message& x) {
  return get<1>(x).content;
}

/// Moves the command content out of a ::command_message. Causes `x` to make a
/// lazy copy of its content if other ::command_message objects hold references
/// to it.
inline internal_command::variant_type&& move_command(command_message& x) {
  return std::move(get<1>(x.unshared()).content);
}

} // namespace broker
