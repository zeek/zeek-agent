#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/izeeklogger.h>

namespace zeek {
/// \brief A virtual table plugin that exposes the logged messages
class ZeekLoggerTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \return A Status object
  static Status create(Ref &obj);

  /// \brief Destructor
  virtual ~ZeekLoggerTablePlugin() override;

  /// \return The table name
  virtual const std::string &name() const override;

  /// \return The table schema
  virtual const Schema &schema() const override;

  /// \brief Generates the row list containing the logged messages
  /// \param row_list Where the generated rows are stored
  /// \return A Status object
  virtual Status generateRowList(RowList &row_list) override;

  /// \brief Used by the logger to store new messages in the table
  /// \param severity The severity for the log message
  /// \param message The message to log
  /// \return A Status object
  Status appendMessage(IZeekLogger::Severity severity,
                       const std::string &message);

protected:
  /// \brief Constructor
  ZeekLoggerTablePlugin();

public:
  /// \brief Generates a single row from the given log message
  /// \param row Where to store the generated row
  /// \param severity The severity for the log message
  /// \param message The message to log
  /// \return A Status object
  static Status generateRow(Row &row, IZeekLogger::Severity severity,
                            const std::string &message);
};
} // namespace zeek
