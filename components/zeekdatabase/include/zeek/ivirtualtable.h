#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <zeek/status.h>

namespace zeek {
class IVirtualTable {
public:
  using Ref = std::shared_ptr<IVirtualTable>;

  using Variant = std::variant<std::int64_t, std::string, double>;
  using OptionalVariant = std::optional<Variant>;

  using Row = std::map<std::string, OptionalVariant>;
  using RowList = std::vector<Row>;

  enum class ColumnType { Integer, String, Double };
  using Schema = std::map<std::string, ColumnType>;

  virtual ~IVirtualTable() = default;
  IVirtualTable() = default;

  virtual const std::string &name() const = 0;
  virtual const Schema &schema() const = 0;
  virtual Status generateRowList(RowList &row_list) = 0;

  IVirtualTable(const IVirtualTable &other) = delete;
  IVirtualTable &operator=(const IVirtualTable &other) = delete;
};
} // namespace zeek
