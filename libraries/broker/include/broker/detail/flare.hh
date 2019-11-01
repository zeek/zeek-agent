#pragma once

#include <cstddef>
#include <chrono>
#include "broker/time.hh"

namespace broker {
namespace detail {

/// An object that can be used to signal a "ready" status via a file descriptor
/// that may be integrated with select(), poll(), etc. Though it may be used to
/// signal availability of a resource across threads, both access to that
/// resource and the use of the fire/extinguish functions must be performed in
/// a thread-safe manner in order for that to work correctly.
class flare {
public:
  using timeout_type = clock::time_point;

  /// Constructs a flare by opening a UNIX pipe.
  flare();

  /// Destructs the flare, closing the UNIX pipe's file descriptors.
  ~flare();

  flare(const flare&) = delete;
  flare& operator=(const flare&) = delete;

  /// Retrieves a file descriptor that will become ready if the flare has been
  /// "fired" and not yet "extinguishedd."
  int fd() const;

  /// Puts the object in the "ready" state by writing `n` bytes into the
  /// underlying pipe.
  void fire(size_t num = 1);

  // Takes the object out of the "ready" state by consuming all bytes from the
  // underlying pipe.
  // @returns the number of consumed bytes
  size_t extinguish();

  /// Attempts to consume only one byte from the pipe, potentially leaving the
  /// flare in "ready" state.
  /// @returns `true` if one byte was read successfully from the pipe and
  ///          `false` if the pipe had no data to be read.
  bool extinguish_one();

  /// Attempts to consume only one byte from the pipe, potentially leaving the
  /// flare in "ready" state.
  /// @returns `true` if one byte was read successfully from the pipe and
  ///          `false` if the pipe had no data to be read.
  size_t extinguish_some(size_t num);

  /// Blocks the caller until the object could consume one byte from the pipe.
  void await_one();

  /// Blocks the caller until the object could consume one byte from the pipe
  /// or or a timeout occurs.
  template <class Timeout>
  bool await_one(Timeout timeout) {
    using clk = typename Timeout::clock;
    auto delta = timeout - clk::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(delta);
    if (ms.count() <= 0)
      return false;
    return await_one_impl(static_cast<int>(ms.count()));
  }

private:
  bool await_one_impl(int ms_timeout);

  int fds_[2];
};

} // namespace detail
} // namespace broker
