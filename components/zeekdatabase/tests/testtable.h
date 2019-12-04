#pragma once

#include <zeek/ivirtualtable.h>

namespace zeek {
class TestTable final : public IVirtualTable {
public:
  enum class SchemaType { Valid, Invalid };

  TestTable(SchemaType schema_type_, std::size_t row_count_ = 1U)
      : schema_type(schema_type_), row_count(row_count_) {}

  virtual ~TestTable() override = default;

  virtual const std::string &name() const override {
    static const std::string kTableName{"TestTable"};
    return kTableName;
  }

  virtual const Schema &schema() const override {
    // clang-format off
    static const Schema kValidTableSchema = {
      { "integer", IVirtualTable::ColumnType::Integer },
      { "string", IVirtualTable::ColumnType::String }
    };
    // clang-format on

    // clang-format off
    static const Schema kInvalidTableSchema = {
      { "integer", static_cast<IVirtualTable::ColumnType>(100) },
      { "string", static_cast<IVirtualTable::ColumnType>(200) }
    };
    // clang-format on

    return schema_type == SchemaType::Valid ? kValidTableSchema
                                            : kInvalidTableSchema;
  }

  virtual Status generateRowList(RowList &row_list) override {
    row_list = {};

    for (auto i = 0U; i < row_count; ++i) {
      Row row = {};
      row.insert({"integer", static_cast<std::int64_t>(i)});
      row.insert({"string", std::to_string(i)});
      row_list.push_back(row);
    }

    return Status::success();
  }

private:
  SchemaType schema_type{SchemaType::Valid};
  std::size_t row_count{0U};
};
} // namespace zeek
