
#include <utility>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <pybind11/pybind11.h>
#pragma GCC diagnostic pop

#include "broker/api_flags.hh"
#include "broker/backend.hh"
#include "broker/error.hh"
#include "broker/frontend.hh"
#include "broker/peer_flags.hh"
#include "broker/peer_status.hh"
#include "broker/status.hh"

namespace py = pybind11;

void init_enums(py::module& m) {
  py::enum_<broker::ec>(m, "EC")
    .value("Unspecified", broker::ec::unspecified)
    .value("PeerIncompatible", broker::ec::peer_incompatible)
    .value("PeerInvalid", broker::ec::peer_invalid)
    .value("PeerUnavailable", broker::ec::peer_unavailable)
    .value("PeerTimeout", broker::ec::peer_timeout)
    .value("MasterExists", broker::ec::master_exists)
    .value("NoSuchMaster", broker::ec::no_such_master)
    .value("NoSuchKey", broker::ec::no_such_key)
    .value("RequestTimeOut", broker::ec::request_timeout)
    .value("TypeClash", broker::ec::type_clash)
    .value("InvalidData", broker::ec::invalid_data)
    .value("BackendFailure", broker::ec::backend_failure)
    .value("StaleData", broker::ec::stale_data);

  py::enum_<broker::sc>(m, "SC")
    .value("Unspecified", broker::sc::unspecified)
    .value("PeerAdded", broker::sc::peer_added)
    .value("PeerRemoved", broker::sc::peer_removed)
    .value("PeerLost", broker::sc::peer_lost);

  py::enum_<broker::peer_status>(m, "PeerStatus")
    .value("Initialized", broker::peer_status::initialized)
    .value("Connecting", broker::peer_status::connecting)
    .value("Connected", broker::peer_status::connected)
    .value("Peered", broker::peer_status::peered)
    .value("Disconnected", broker::peer_status::disconnected)
    .value("Reconnecting", broker::peer_status::reconnecting);

  py::enum_<broker::peer_flags>(m, "PeerFlags")
    .value("Invalid", broker::peer_flags::invalid)
    .value("Local", broker::peer_flags::local)
    .value("Remote", broker::peer_flags::remote)
    .value("Outbound", broker::peer_flags::outbound)
    .value("Inbound", broker::peer_flags::inbound);

  py::enum_<broker::api_flags>(m, "APIFlags")
    .value("Blocking", broker::blocking)
    .value("NonBlocking", broker::nonblocking)
    .export_values();

  py::enum_<broker::frontend>(m, "Frontend")
    .value("Master", broker::master)
    .value("Clone", broker::clone)
    .export_values();

  py::enum_<broker::backend>(m, "Backend")
    .value("Memory", broker::memory)
    .value("SQLite", broker::sqlite)
    .value("RocksDB", broker::rocksdb)
    .export_values();
}
