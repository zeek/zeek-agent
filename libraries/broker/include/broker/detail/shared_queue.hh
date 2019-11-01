#pragma once

#include <atomic>
#include <deque>
#include <mutex>
#include <thread>
#include <condition_variable>

#include <caf/duration.hpp>
#include <caf/ref_counted.hpp>

#include "broker/data.hh"
#include "broker/message.hh"
#include "broker/topic.hh"

#include "broker/detail/flare.hh"

namespace broker {
namespace detail {

/// Base class for `shared_publisher_queue` and `shared_subscriber_queue`.
template <class ValueType = data_message>
class shared_queue : public caf::ref_counted {
public:
  using value_type = ValueType;

  using guard_type = std::unique_lock<std::mutex>;

  // --- accessors -------------------------------------------------------------

  int fd() const {
    return fx_.fd();
  }

  long pending() const {
    return pending_.load();
  }

  long rate() const {
    return rate_.load();
  }

  size_t buffer_size() const {
    guard_type guard{mtx_};
    return xs_.size();
  }

  // --- mutators --------------------------------------------------------------

  void pending(long x) {
    pending_ = x;
  }

  void rate(long x) {
    rate_ = x;
  }

  void wait_on_flare() {
    fx_.await_one();
  }

  bool wait_on_flare(caf::duration timeout) {
    if (!timeout.valid()) {
      fx_.await_one();
      return true;
    }
    auto abs_timeout = std::chrono::high_resolution_clock::now();
    abs_timeout += timeout;
    return fx_.await_one(abs_timeout);
  }

  template <class T>
  bool wait_on_flare_abs(T abs_timeout) {
    return fx_.await_one(abs_timeout);
  }

protected:
  shared_queue() : pending_(0) {
    // nop
  }

  /// Guards access to `xs`.
  mutable std::mutex mtx_;

  /// Signals to users when data can be read or written.
  mutable flare fx_;

  /// Buffers values received by the worker.
  std::deque<value_type> xs_;

  /// Stores what demand the worker has last signaled to the core or vice
  /// versa, depending on the message direction.
  std::atomic<long> pending_;

  /// Stores consumption or production rate.
  std::atomic<size_t> rate_;
};

} // namespace detail
} // namespace broker
