#pragma once

#include <caf/intrusive_ptr.hpp>
#include <caf/make_counted.hpp>

#include "broker/detail/assert.hh"
#include "broker/detail/shared_queue.hh"
#include "broker/message.hh"

namespace broker {
namespace detail {

/// Synchronizes a publisher with a background worker. Uses the `pending` flag
/// and the `flare` to signalize demand to the user. Users can write as long as
/// the flare remains active. The worker consumes items, while the user
/// produces them.
///
/// The protocol on the flare is as follows:
/// - the flare starts active
/// - the flare is active as long as xs_ has below 20 items
/// - consume() fires the flare when it removes items from xs_ and less than 20
///   items remain
/// - produce() extinguishes the flare it adds items to xs_, exceeding 20
template <class ValueType = data_message>
class shared_publisher_queue : public shared_queue<ValueType> {
public:
  using value_type = ValueType;

  using super = shared_queue<ValueType>;

  using guard_type = typename super::guard_type;

  shared_publisher_queue(size_t buffer_size) : capacity_(buffer_size) {
    // The flare is active as long as publishers can write.
    this->fx_.fire();
  }

  // Called to pull items out of the queue. Signals demand to the user if less
  // than `num` items can be published from the buffer. When calling consume
  // again after an unsuccessful run, `num` must not be smaller than on the
  // previous call. Otherwise, the demand signaled on the flare runs out of
  // sync.
  template <class F>
  size_t consume(size_t num, F fun) {
    guard_type guard{this->mtx_};
    auto& xs = this->xs_;
    if (xs.empty()) {
      this->pending_ = static_cast<long>(num);
      return false;
    }
    auto n = std::min(num, xs.size());
    auto b = xs.begin();
    auto e = b + static_cast<ptrdiff_t>(n);
    for (auto i = b; i != e; ++i)
      fun(std::move(*i));
    auto old_size = xs.size();
    xs.erase(b, e);
    auto new_size = xs.size();
    // Extinguish the flare if we reach the capacity or fire it if we drop
    // below the capacity again.
    if (new_size >= capacity_ && old_size < capacity_)
      this->fx_.extinguish();
    else if (new_size < capacity_ && old_size >= capacity_)
      this->fx_.fire();
    if (num - n > 0)
      this->pending_ = static_cast<long>(num - n);
    return n;
  }

  /// Returns true if the caller must wake up the consumer. This function can
  /// go beyond the capacity of the queue.
  template <class Iterator>
  bool produce(const topic& t, Iterator first, Iterator last) {
    guard_type guard{this->mtx_};
    auto& xs = this->xs_;
    if (xs.size() >= capacity_)
      await_consumer(guard);
    auto xs_old_size = xs.size();
    BROKER_ASSERT(xs_old_size < capacity_);
    for (; first != last; ++first)
      xs.emplace_back(t, std::move(*first));
    if (xs.size() >= capacity_) {
      // Extinguish the flare to cause the *next* produce to block.
      this->fx_.extinguish();
    }
    return xs_old_size == 0;
  }

  // Returns true if the caller must wake up the consumer.
  bool produce(const topic& t, data&& y) {
    guard_type guard{this->mtx_};
    auto& xs = this->xs_;
    if (xs.size() >= capacity_)
      await_consumer(guard);
    auto xs_old_size = xs.size();
    BROKER_ASSERT(xs_old_size < capacity_);
    xs.emplace_back(t, std::move(y));
    if (xs.size() >= capacity_) {
      // Extinguish the flare to cause the *next* produce to block.
      this->fx_.extinguish();
    }
    return xs_old_size == 0;
  }

  size_t capacity() const {
    return capacity_;
  }

private:
  void await_consumer(guard_type& guard) {
    // Block the caller until the consumer catched up.
    guard.unlock();
    this->fx_.await_one();
    guard.lock();
  }

  /// @pre xs.size() < capacity_
  ptrdiff_t free_space() {
    return static_cast<ptrdiff_t>(capacity_ - this->xs.size());
  }


  // Configures the amound of items for xs_.
  const size_t capacity_;
};

template <class ValueType = data_message>
using shared_publisher_queue_ptr
  = caf::intrusive_ptr<shared_publisher_queue<ValueType>>;

template <class ValueType = data_message>
shared_publisher_queue_ptr<ValueType>
make_shared_publisher_queue(size_t buffer_size) {
  return caf::make_counted<shared_publisher_queue<ValueType>>(buffer_size);
}

} // namespace detail
} // namespace broker
