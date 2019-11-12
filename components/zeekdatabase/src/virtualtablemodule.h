#pragma once

#include <sqlite3.h>

#include <zeek/ivirtualtable.h>
#include <zeek/status.h>

namespace zeek {
class VirtualTableModule final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  using Ref = std::unique_ptr<VirtualTableModule>;

  static Status create(Ref &obj, IVirtualTable::Ref table);
  ~VirtualTableModule();

  const std::string &name() const;

  VirtualTableModule(const VirtualTableModule &other) = delete;
  VirtualTableModule &operator=(const VirtualTableModule &other) = delete;

private:
  VirtualTableModule(IVirtualTable::Ref table);

public:
  static const struct sqlite3_module *sqliteModule();

  static Status generateSQLTableDefinition(std::string &sql_statement,
                                           IVirtualTable::Ref table);

  static int onTableClose(sqlite3_vtab_cursor *cursor);
  static int onTableEof(sqlite3_vtab_cursor *cursor);
  static int onTableNext(sqlite3_vtab_cursor *cursor);
  static int onTableColumn(sqlite3_vtab_cursor *cursor,
                           sqlite3_context *context, int i);

  static int onTableOpen(sqlite3_vtab *table_instance,
                         sqlite3_vtab_cursor **cursor);

  static int onTableDisconnect(sqlite3_vtab *table_instance);

  static int onTableRowid(sqlite3_vtab_cursor *cursor, sqlite3_int64 *rowid);

  static int onTableCreate(sqlite3 *sqlite_database,
                           void *virtual_table_module_ptr, int,
                           const char *const *, sqlite3_vtab **table_instance,
                           char **);

  static int onTableFilter(sqlite3_vtab_cursor *cursor, int, const char *, int,
                           sqlite3_value **);
};
} // namespace zeek
