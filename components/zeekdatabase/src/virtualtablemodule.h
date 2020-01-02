#pragma once

#include <sqlite3.h>

#include <zeek/ivirtualtable.h>
#include <zeek/status.h>

namespace zeek {
/// \brief A wrapper for SQLite virtual table modules
class VirtualTableModule final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief A reference to a virtual table module object
  using Ref = std::unique_ptr<VirtualTableModule>;

  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \param table The virtual table plugin to service
  static Status create(Ref &obj, IVirtualTable::Ref table);

  /// \brief Destructor
  ~VirtualTableModule();

  /// \return The module name
  const std::string &name() const;

  VirtualTableModule(const VirtualTableModule &other) = delete;
  VirtualTableModule &operator=(const VirtualTableModule &other) = delete;

private:
  /// \brief Constructor
  /// \param table The table to service
  VirtualTableModule(IVirtualTable::Ref table);

public:
  /// \return The low level SQLite module structure
  static const struct sqlite3_module *sqliteModule();

  /// \brief Generates a SQL statement that defines the given table
  /// \param sql_statement Where the generated SQL statement is created
  /// \param table The virtual table plugin from which the schema is taken
  /// \return A Status object
  static Status generateSQLTableDefinition(std::string &sql_statement,
                                           IVirtualTable::Ref table);

  /// \brief xClose wrapper (see the SQLite docs for more information)
  static int onTableClose(sqlite3_vtab_cursor *cursor);

  /// \brief xEof wrapper (see the SQLite docs for more information)
  static int onTableEof(sqlite3_vtab_cursor *cursor);

  /// \brief xNext wrapper (see the SQLite docs for more information)
  static int onTableNext(sqlite3_vtab_cursor *cursor);

  /// \brief xColumn wrapper (see the SQLite docs for more information)
  static int onTableColumn(sqlite3_vtab_cursor *cursor,
                           sqlite3_context *context, int i);

  /// \brief xOpen wrapper (see the SQLite docs for more information)
  static int onTableOpen(sqlite3_vtab *table_instance,
                         sqlite3_vtab_cursor **cursor);

  /// \brief xDisconnect wrapper (see the SQLite docs for more information)
  static int onTableDisconnect(sqlite3_vtab *table_instance);

  /// \brief xRowid wrapper (see the SQLite docs for more information)
  static int onTableRowid(sqlite3_vtab_cursor *cursor, sqlite3_int64 *rowid);

  /// \brief xCreate wrapper (see the SQLite docs for more information)
  static int onTableCreate(sqlite3 *sqlite_database,
                           void *virtual_table_module_ptr, int,
                           const char *const *, sqlite3_vtab **table_instance,
                           char **);

  /// \brief xFilter wrapper (see the SQLite docs for more information)
  static int onTableFilter(sqlite3_vtab_cursor *cursor, int, const char *, int,
                           sqlite3_value **);
};
} // namespace zeek
