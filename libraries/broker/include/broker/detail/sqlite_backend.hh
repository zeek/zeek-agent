#pragma once

#include "broker/backend_options.hh"

#include "broker/detail/abstract_backend.hh"

namespace broker {
namespace detail {

/// A SQLite storage backend.
class sqlite_backend : public abstract_backend {
public:
  /// Constructs a SQLite backend.
  /// @param opts The options to create/open a database.
  /// Required parameters:
  ///   - `path`: a `std::string` representing the location of the database on
  ///             the filesystem.
  sqlite_backend(backend_options opts = backend_options{});

  ~sqlite_backend();

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

  expected<bool> exists(const data& key) const override;

  expected<uint64_t> size() const override;

  expected<data> keys() const override;

  expected<broker::snapshot> snapshot() const override;

  expected<expirables> expiries() const override;

private:
  struct impl;
  std::unique_ptr<impl> impl_;
};

} // namespace detail
} // namespace broker
