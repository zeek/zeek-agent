#pragma once

#include "broker/data.hh"

namespace broker {
namespace zeek {

const count ProtocolVersion = 1;

/// Generic Zeek-level message.
class Message {
public:
  enum Type {
    Invalid = 0,
    Event = 1,
    LogCreate = 2,
    LogWrite = 3,
    IdentifierUpdate = 4,
    Batch = 5,
    MAX = Batch,
  };

  Type type() const {
    if ( as_vector().size() < 2 )
      return Type::Invalid;

    auto cp = caf::get_if<count>(&as_vector()[1]);

    if ( ! cp )
      return Type::Invalid;

    if ( *cp > Type::MAX )
      return Type::Invalid;

    return Type(*cp);
  }

  data&& move_data() {
    return std::move(data_);
  }

  const data& as_data() const {
    return data_;
  }

  data& as_data() {
    return data_;
  }

  const vector& as_vector() const {
    return caf::get<vector>(data_);
  }

  vector& as_vector() {
    return caf::get<vector>(data_);
   }

  operator data() const {
    return as_data();
  }

  static Type type(const data& msg) {
    auto vp = caf::get_if<vector>(&msg);

    if ( ! vp )
      return Type::Invalid;

    auto& v = *vp;

    if ( v.size() < 2 )
      return Type::Invalid;

    auto cp = caf::get_if<count>(&v[1]);

    if ( ! cp )
      return Type::Invalid;

    if ( *cp > Type::MAX )
      return Type::Invalid;

    return Type(*cp);
  }

protected:
  Message(Type type, vector content)
    : data_(vector{ProtocolVersion, count(type), std::move(content)}) {
  }

  Message(data msg) : data_(std::move(msg)) {
  }

  data data_;
};

/// A Zeek event.
class Event : public Message {
  public:
  Event(std::string name, vector args)
    : Message(Message::Type::Event, {std::move(name), std::move(args)}) {}

  Event(data msg) : Message(std::move(msg)) {}

  const std::string& name() const {
    return caf::get<std::string>(caf::get<vector>(as_vector()[2])[0]);
  }

  std::string& name() {
    return caf::get<std::string>(caf::get<vector>(as_vector()[2])[0]);
  }

  const vector& args() const {
    return caf::get<vector>(caf::get<vector>(as_vector()[2])[1]);
  }

  vector& args() {
    return caf::get<vector>(caf::get<vector>(as_vector()[2])[1]);
  }

  bool valid() const {
    if ( as_vector().size() < 3 )
      return false;

    auto vp = caf::get_if<vector>(&(as_vector()[2]));

    if ( ! vp )
      return false;

    auto& v = *vp;

    if ( v.size() < 2 )
      return false;

    auto name_ptr = caf::get_if<std::string>(&v[0]);

    if ( ! name_ptr )
      return false;

    auto args_ptr = caf::get_if<vector>(&v[1]);

    if ( ! args_ptr )
      return false;

    return true;
  }
};

/// A batch of other messages.
class Batch : public Message {
  public:
  Batch(vector msgs)
    : Message(Message::Type::Batch, std::move(msgs)) {}

  Batch(data msg) : Message(std::move(msg)) {}

  const vector& batch() const {
    return caf::get<vector>(as_vector()[2]);
  }

  vector& batch() {
    return caf::get<vector>(as_vector()[2]);
  }

  bool valid() const {
    if ( as_vector().size() < 3 )
      return false;

    auto vp = caf::get_if<vector>(&(as_vector()[2]));

    if ( ! vp )
      return false;

    return true;
  }
};

/// A Zeek log-create message. Note that at the moment this should be used
/// only by Zeek itself as the arguments aren't pulbically defined.
class LogCreate : public Message {
public:
  LogCreate(enum_value stream_id, enum_value writer_id, data writer_info,
            data fields_data)
    : Message(Message::Type::LogCreate,
              {std::move(stream_id), std::move(writer_id),
               std::move(writer_info), std::move(fields_data)}) {
  }

  LogCreate(data msg) : Message(std::move(msg)) {
  }

  const enum_value& stream_id() const {
    return caf::get<enum_value>(caf::get<vector>(as_vector()[2])[0]);
  }

  enum_value& stream_id() {
    return caf::get<enum_value>(caf::get<vector>(as_vector()[2])[0]);
  }

  const enum_value& writer_id() const {
    return caf::get<enum_value>(caf::get<vector>(as_vector()[2])[1]);
  }

  enum_value& writer_id() {
    return caf::get<enum_value>(caf::get<vector>(as_vector()[2])[1]);
  }

  const data& writer_info() const {
    return caf::get<vector>(as_vector()[2])[2];
  }

  data& writer_info() {
    return caf::get<vector>(as_vector()[2])[2];
  }

  const data& fields_data() const {
    return caf::get<vector>(as_vector()[2])[3];
  }

  data& fields_data() {
    return caf::get<vector>(as_vector()[2])[3];
  }

  bool valid() const {
    if ( as_vector().size() < 3 )
      return false;

    auto vp = caf::get_if<vector>(&(as_vector()[2]));

    if ( ! vp )
      return false;

    auto& v = *vp;

    if ( v.size() < 4 )
      return false;

    if ( ! caf::get_if<enum_value>(&v[0]) )
      return false;

    if ( ! caf::get_if<enum_value>(&v[1]) )
      return false;

    return true;
  }
};

/// A Zeek log-write message. Note that at the moment this should be used only
/// by Zeek itself as the arguments aren't publicly defined.
class LogWrite : public Message {
public:
  LogWrite(enum_value stream_id, enum_value writer_id, data path,
           data serial_data)
    : Message(Message::Type::LogWrite,
              {std::move(stream_id), std::move(writer_id),
               std::move(path), std::move(serial_data)}) {
  }

  LogWrite(data msg) : Message(std::move(msg)) {
  }

  const enum_value& stream_id() const {
    return caf::get<enum_value>(caf::get<vector>(as_vector()[2])[0]);
  }

  enum_value& stream_id() {
    return caf::get<enum_value>(caf::get<vector>(as_vector()[2])[0]);
  }

  const enum_value& writer_id() const {
    return caf::get<enum_value>(caf::get<vector>(as_vector()[2])[1]);
  }

  enum_value& writer_id() {
    return caf::get<enum_value>(caf::get<vector>(as_vector()[2])[1]);
  }

  const data& path() const {
    return caf::get<vector>(as_vector()[2])[2];
  }

  data& path() {
    return caf::get<vector>(as_vector()[2])[2];
  };

  const data& serial_data() const {
    return caf::get<vector>(as_vector()[2])[3];
  }

  data& serial_data() {
    return caf::get<vector>(as_vector()[2])[3];
  }

  bool valid() const {
    if ( as_vector().size() < 3 )
      return false;

    auto vp = caf::get_if<vector>(&(as_vector()[2]));

    if ( ! vp )
      return false;

    auto& v = *vp;

    if ( v.size() < 4 )
      return false;

    if ( ! caf::get_if<enum_value>(&v[0]) )
      return false;

    if ( ! caf::get_if<enum_value>(&v[1]) )
      return false;

    return true;
  }
};

class IdentifierUpdate : public Message {
public:
  IdentifierUpdate(std::string id_name, data id_value)
    : Message(Message::Type::IdentifierUpdate, {std::move(id_name),
    		                                    std::move(id_value)}) {
  }

  IdentifierUpdate(data msg) : Message(std::move(msg)) {
  }

  const std::string& id_name() const {
    return caf::get<std::string>(caf::get<vector>(as_vector()[2])[0]);
  }

  std::string& id_name() {
    return caf::get<std::string>(caf::get<vector>(as_vector()[2])[0]);
  }

  const data& id_value() const {
    return caf::get<vector>(as_vector()[2])[1];
  }

  data& id_value() {
    return caf::get<vector>(as_vector()[2])[1];
  }

  bool valid() const {
    if ( as_vector().size() < 3 )
      return false;

    auto vp = caf::get_if<vector>(&(as_vector()[2]));

    if ( ! vp )
      return false;

    auto& v = *vp;

    if ( v.size() < 2 )
      return false;

    if ( ! caf::get_if<std::string>(&v[0]) )
      return false;

    return true;
  }
};

} // namespace broker
} // namespace zeek
