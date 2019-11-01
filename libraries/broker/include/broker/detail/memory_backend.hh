#pragma once

#include <unordered_map>

#include "broker/backend_options.hh"

#include "broker/detail/abstract_backend.hh"

namespace broker {
namespace detail {

/// An in-memory key-value storage backend.
class memory_backend : public abstract_backend {
public:
  /// Constructs a memory backend.
  /// @param opts The options controlling the backend behavior.
  memory_backend(backend_options opts = backend_options{});

  expected<void> put(const data& key, data value,
                     optional<timestamp> expiry) override;

  expected<void> add(const data& key, const data& value, data::type init_type,
                     optional<timestamp> expiry) override;

  expected<void> subtract(const data& key, const data& value,
                          optional<timestamp> expiry) override;

  expected<void> erase(const data& key) override;

  expected<void> clear() override;

  expected<bool> expire(const data& key, timestamp current_time) override;

  expected<data> get(const data& key) const override;

  expected<data> get(const data& key, const data& value) const override;

  expected<bool> exists(const data& key) const override;

  expected<uint64_t> size() const override;

  expected<data> keys() const override;

  expected<broker::snapshot> snapshot() const override;

  expected<expirables> expiries() const override;

private:
  backend_options options_;
  std::unordered_map<data, std::pair<data, optional<timestamp>>> store_;
  std::unordered_map<data, timestamp> expirations_;
};

} // namespace detail
} // namespace broker
