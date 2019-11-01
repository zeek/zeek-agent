#pragma once

#include <string>

#include "broker/backend_options.hh"

#include "broker/detail/abstract_backend.hh"

namespace broker {
namespace detail {

/// A RocksDB storage backend.
class rocksdb_backend : public abstract_backend {
public:
  /// Constructs a RocksDB backend.
  /// @param opts The options to create/open a database.
  ///
  /// Required:
  ///   - `path`: a `std::string` representing the location of the database on
  ///             the filesystem.
  ///
  /// Optional:
  ///   - `exact_size_threshold`: a `count` that represents the threshold when
  ///                             to start estimating the nubmer of keys as
  ///                             opposed to linear enumeration.
  ///                             (default = 10,000)
  rocksdb_backend(backend_options opts = backend_options{});

  ~rocksdb_backend();

  expected<void> put(const data& key, data value,
                     optional<timestamp> expiry) override;

  expected<void> add(const data& key, const data& value,
                     data::type init_type,
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
  bool open_db();

  struct impl;
  std::unique_ptr<impl> impl_;
};

} // namespace detail
} // namespace broker
