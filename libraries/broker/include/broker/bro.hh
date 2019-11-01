#pragma once

#pragma message("Warning: bro.hh header is deprecated, use zeek.hh instead")

#ifdef __GNUC__
  #define BROKER_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
#else
  #define BROKER_DEPRECATED(msg)
#endif

#include "broker/zeek.hh"

namespace broker {
namespace bro {

using Message
      BROKER_DEPRECATED("use version from zeek.hh and zeek namespace instead")
      = broker::zeek::Message;

using Event
      BROKER_DEPRECATED("use version from zeek.hh and zeek namespace instead")
      = broker::zeek::Event;

using Batch
      BROKER_DEPRECATED("use version from zeek.hh and zeek namespace instead")
      = broker::zeek::Batch;

using LogCreate
      BROKER_DEPRECATED("use version from zeek.hh and zeek namespace instead")
      = broker::zeek::LogCreate;

using LogWrite
      BROKER_DEPRECATED("use version from zeek.hh and zeek namespace instead")
      = broker::zeek::LogWrite;

using IdentifierUpdate
      BROKER_DEPRECATED("use version from zeek.hh and zeek namespace instead")
      = broker::zeek::IdentifierUpdate;

} // namespace broker
} // namespace bro
