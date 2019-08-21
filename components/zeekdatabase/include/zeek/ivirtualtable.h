#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include <zeek/status.h>

namespace zeek {
class IVirtualTable {
public:
  using Ref = std::unique_ptr<IVirtualTable>;

  struct Value final {
    enum class ColumnType { Integer, String };

    ColumnType type;
    std::variant<std::int64_t, std::string> data;
  };

  using Row = std::unordered_map<std::string, Value>;
  using RowList = std::vector<Row>;

  using Schema = std::unordered_map<std::string, Value::ColumnType>;

  virtual ~IVirtualTable() = default;
  IVirtualTable() = default;

  virtual const std::string &name() const = 0;
  virtual const Schema &schema() const = 0;
  virtual Status generateRowList(RowList &row_list) = 0;

  IVirtualTable(const IVirtualTable &other) = delete;
  IVirtualTable &operator=(const IVirtualTable &other) = delete;
};
} // namespace zeek
