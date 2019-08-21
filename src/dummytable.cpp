#include "dummytable.h"

namespace zeek {
namespace {
DummyTable::Schema kTableSchema = {
    {"integer", IVirtualTable::Value::ColumnType::Integer},
    {"string", IVirtualTable::Value::ColumnType::String}};
}

struct DummyTable::PrivateData final {
  std::string name;
  Schema schema;
};

Status DummyTable::create(Ref &obj) {
  obj.reset();

  try {
    auto ptr = new DummyTable();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

DummyTable::~DummyTable() {}

const std::string &DummyTable::name() const { return d->name; }

const DummyTable::Schema &DummyTable::schema() const { return d->schema; }

Status DummyTable::generateRowList(RowList &row_list) {
  row_list = {};

  Row row;
  row.insert({"integer", {IVirtualTable::Value::ColumnType::Integer, 0}});
  row.insert({"string", {IVirtualTable::Value::ColumnType::String, "0"}});
  row_list.push_back(row);

  row = {};
  row.insert({"integer", {IVirtualTable::Value::ColumnType::Integer, 1}});
  row.insert({"string", {IVirtualTable::Value::ColumnType::String, "1"}});
  row_list.push_back(row);

  row = {};
  row.insert({"integer", {IVirtualTable::Value::ColumnType::Integer, 2}});
  row.insert({"string", {IVirtualTable::Value::ColumnType::String, "2"}});
  row_list.push_back(row);

  return Status::success();
}

DummyTable::DummyTable() : d(new PrivateData) {
  d->name = "dummy_table";
  d->schema = kTableSchema;
}
} // namespace zeek
