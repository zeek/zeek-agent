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
      { "integer", IVirtualTable::Value::ColumnType::Integer },
      { "string", IVirtualTable::Value::ColumnType::String }
    };
    // clang-format on

    // clang-format off
    static const Schema kInvalidTableSchema = {
      { "integer", static_cast<IVirtualTable::Value::ColumnType>(100) },
      { "string", static_cast<IVirtualTable::Value::ColumnType>(200) }
    };
    // clang-format on

    return schema_type == SchemaType::Valid ? kValidTableSchema
                                            : kInvalidTableSchema;
  }

  virtual Status generateRowList(RowList &row_list) override {
    row_list = {};

    auto integer_column_type =
        (schema_type == SchemaType::Valid)
            ? IVirtualTable::Value::ColumnType::Integer
            : static_cast<IVirtualTable::Value::ColumnType>(100);

    auto string_column_type =
        (schema_type == SchemaType::Valid)
            ? IVirtualTable::Value::ColumnType::String
            : static_cast<IVirtualTable::Value::ColumnType>(200);

    for (auto i = 0U; i < row_count; ++i) {
      Row row = {};
      row.insert({"integer", {integer_column_type, i}});
      row.insert({"string", {string_column_type, std::to_string(i)}});
      row_list.push_back(row);
    }

    return Status::success();
  }

private:
  SchemaType schema_type{SchemaType::Valid};
  std::size_t row_count{0U};
};
} // namespace zeek
