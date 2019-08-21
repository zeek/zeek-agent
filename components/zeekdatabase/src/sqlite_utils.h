#pragma once

#include <memory>

#include <sqlite3.h>

#include <zeek/status.h>

namespace zeek {
struct SqliteStatementDeleter final {
  void operator()(sqlite3_stmt *obj);
};

using SqliteStatement = std::unique_ptr<sqlite3_stmt, SqliteStatementDeleter>;

struct Sqlite3MemoryDeleter final {
  void operator()(void *ptr) {
    if (ptr == nullptr) {
      return;
    }

    sqlite3_free(ptr);
  }
};

using Sqlite3MemoryRef = std::unique_ptr<void, Sqlite3MemoryDeleter>;

Status prepareSqliteStatement(SqliteStatement &obj, sqlite3 *database,
                              const std::string &query);

Status validateSqliteName(const std::string &name);

Status allocateSqliteMemory(Sqlite3MemoryRef &obj, std::size_t size);
} // namespace zeek
