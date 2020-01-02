#pragma once

#include <atomic>
#include <memory>

#include <zeek/ivirtualdatabase.h>
#include <zeek/status.h>

namespace zeek {
/// \brief Schedules queries against the virtual database
class QueryScheduler final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief A reference to a query scheduler object
  using Ref = std::unique_ptr<QueryScheduler>;

  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \param virtual_database The reference to a valid virtual database
  /// \return A Status object
  static Status create(Ref &obj, IVirtualDatabase &virtual_database);

  /// \brief Destructor
  ~QueryScheduler();

  /// \brief A scheduled task
  struct Task final {
    /// \brief Available task types
    enum class Type { AddScheduledQuery, RemoveScheduledQuery, ExecuteQuery };

    /// \brief Available update types
    enum class UpdateType { Added, Removed, Both };

    /// \brief The task type
    Type type;

    /// \brief The task query
    std::string query;

    /// \brief The task event name
    std::string response_event;

    /// \brief The response topic for this task
    std::string response_topic;

    /// \brief The task id
    std::string cookie;

    /// \brief Schedule interval
    std::optional<std::uint64_t> interval;

    /// \brief Requested update type (differential)
    std::optional<UpdateType> update_type;
  };

  /// \brief A list of tasks to process
  using TaskQueue = std::vector<Task>;

  /// \brief The output for a single task
  struct TaskOutput final {
    /// \brief The response topic for this task
    std::string response_topic;

    /// \brief The response event name for this task
    std::string response_event;

    /// \brief The task id
    std::string cookie;

    /// \brief The update types this task is interested in
    std::optional<Task::UpdateType> update_type;

    /// \brief The query output for this task
    IVirtualDatabase::QueryOutput query_output;
  };

  /// \brief A list of task outputs
  using TaskOutputList = std::vector<TaskOutput>;

  /// \brief Processes the given task queue, updating the internal state
  /// \param task_queue The task queue to process
  void processTaskQueue(TaskQueue task_queue);

  /// \brief Processes the query schedules, updating the internal state
  /// \return A Status object
  Status processEvents();

  /// \return The output for the running tasks
  TaskOutputList getTaskOutputList();

  /// \brief Starts the internal query scheduler services
  /// \return A Status object
  Status start();

  /// \brief Stops the internal query scheduler services
  void stop();

  QueryScheduler(const QueryScheduler &) = delete;
  QueryScheduler &operator=(const QueryScheduler &) = delete;

protected:
  /// \brief Constructor
  QueryScheduler(IVirtualDatabase &virtual_database);

private:
  /// \brief Executes a single task, updating the internal state
  /// \param task The task to execute
  /// \return A Status object
  Status executeTask(const Task &task);
};
} // namespace zeek
