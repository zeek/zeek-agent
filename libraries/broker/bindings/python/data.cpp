
#include <cstdint>
#include <utility>
#include <array>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <pybind11/pybind11.h>
#pragma GCC diagnostic pop

#include "set_bind.h"

#include "broker/data.hh"
#include "broker/convert.hh"
#include "broker/detail/assert.hh"
#include "broker/detail/operators.hh"

namespace py = pybind11;
using namespace pybind11::literals;

void init_data(py::module& m) {

  py::class_<broker::address> address_type{m, "Address"};
  address_type.def(py::init<>())
    .def(py::init([](const py::bytes& bytes, int family) {
        BROKER_ASSERT(family == 4 || family == 6);
        auto str = static_cast<std::string>(bytes);
        auto ptr = reinterpret_cast<const uint32_t*>(str.data());
        auto f = family == 4 ? broker::address::family::ipv4 :
                               broker::address::family::ipv6;
        return broker::address{ptr, f, broker::address::byte_order::network};
        }))
    .def("mask", &broker::address::mask, "top_bits_to_keep"_a)
    .def("is_v4", &broker::address::is_v4)
    .def("is_v6", &broker::address::is_v6)
    .def("bytes", [](const broker::address& a) {
        return py::bytes(std::string(std::begin(a.bytes()), std::end(a.bytes())));
        })
    .def("__repr__",
         [](const broker::address& a) { return broker::to_string(a); })
    .def(py::self < py::self)
    .def(py::self <= py::self)
    .def(py::self > py::self)
    .def(py::self >= py::self)
    .def(py::self == py::self)
    .def(py::self != py::self);

  py::enum_<broker::address::family>(address_type, "Family")
    .value("IPv4", broker::address::family::ipv4)
    .value("IPv6", broker::address::family::ipv6);

  py::enum_<broker::address::byte_order>(address_type, "ByteOrder")
    .value("Host", broker::address::byte_order::host)
    .value("Network", broker::address::byte_order::network);

  // A thin wrapper around the 'count' type, because Python has no notion of
  // unsigned integers.
  struct count_type {
    count_type(broker::count c) : value{c} {}
    bool operator==(const count_type& other) const { return value == other.value; }
    bool operator!=(const count_type& other) const { return value != other.value; }
    bool operator<(const count_type& other) const { return value < other.value; }
    bool operator<=(const count_type& other) const { return value <= other.value; }
    bool operator>(const count_type& other) const { return value > other.value; }
    bool operator>=(const count_type& other) const { return value >= other.value; }
    broker::count value;
  };

  py::class_<count_type>(m, "Count")
    .def(py::init<py::int_>())
    .def_readwrite("value", &count_type::value)
    .def("__str__", [](const count_type& c) { return broker::to_string(c.value); })
    .def("__repr__", [](const count_type& c) { return "Count(" + broker::to_string(c.value) + ")"; })
    .def(py::self < py::self)
    .def(py::self <= py::self)
    .def(py::self > py::self)
    .def(py::self >= py::self)
    .def(py::self == py::self)
    .def(py::self != py::self);

  py::class_<broker::enum_value>{m, "Enum"}
    .def(py::init<std::string>())
    .def_readwrite("name", &broker::enum_value::name)
    .def("__repr__", [](const broker::enum_value& e) { return broker::to_string(e); })
    .def(py::self < py::self)
    .def(py::self <= py::self)
    .def(py::self > py::self)
    .def(py::self >= py::self)
    .def(py::self == py::self)
    .def(py::self != py::self);

  py::class_<broker::port> port_type{m, "Port"};
  port_type
    .def(py::init<>())
    .def(py::init<broker::port::number_type, broker::port::protocol>())
    .def("number", &broker::port::number)
    .def("get_type", &broker::port::type)
    .def("__repr__", [](const broker::port& p) { return broker::to_string(p); })
    .def(py::self < py::self)
    .def(py::self <= py::self)
    .def(py::self > py::self)
    .def(py::self >= py::self)
    .def(py::self == py::self)
    .def(py::self != py::self);

  py::enum_<broker::port::protocol>(port_type, "Protocol")
    .value("ICMP", broker::port::protocol::icmp)
    .value("TCP", broker::port::protocol::tcp)
    .value("UDP", broker::port::protocol::udp)
    .value("Unknown", broker::port::protocol::unknown)
    .export_values();

  py::bind_set<broker::set>(m, "Set");

  py::bind_map<broker::table>(m, "Table");

  py::class_<broker::subnet>(m, "Subnet")
    .def(py::init<>())
    .def(py::init([](broker::address addr, uint8_t length) {
        return broker::subnet(std::move(addr), length);
        }))
    .def("contains", &broker::subnet::contains, "addr"_a)
    .def("network", &broker::subnet::network)
    .def("length", &broker::subnet::length)
    .def("__repr__", [](const broker::subnet& sn) { return to_string(sn); })
    .def(py::self < py::self)
    .def(py::self <= py::self)
    .def(py::self > py::self)
    .def(py::self >= py::self)
    .def(py::self == py::self)
    .def(py::self != py::self);

  py::class_<broker::timespan>(m, "Timespan")
    .def(py::init<>())
    .def(py::init<broker::integer>())
    .def(py::init([](double secs) {
        return broker::to_timespan(secs);
        }))
    .def("count", &broker::timespan::count)
    .def("__repr__", [](const broker::timespan& s) { return broker::to_string(s); })
    .def(py::self + py::self)
    .def(py::self - py::self)
    .def(py::self * broker::timespan::rep{})
    .def(broker::timespan::rep{} * py::self)
    .def(py::self / py::self)
    .def(py::self / broker::timespan::rep{})
    .def(py::self % py::self)
    .def(py::self % broker::timespan::rep{})
    .def(py::self < py::self)
    .def(py::self <= py::self)
    .def(py::self > py::self)
    .def(py::self >= py::self)
    .def(py::self == py::self)
    .def(py::self != py::self);

  py::class_<broker::timestamp>(m, "Timestamp")
    .def(py::init<>())
    .def(py::init<broker::timespan>())
    .def(py::init([](double secs) {
        return broker::to_timestamp(secs);
        }))
    .def("time_since_epoch", &broker::timestamp::time_since_epoch)
    .def("__repr__", [](const broker::timestamp& ts) { return broker::to_string(ts); })
    .def(py::self < py::self)
    .def(py::self <= py::self)
    .def(py::self > py::self)
    .def(py::self >= py::self)
    .def(py::self == py::self)
    .def(py::self != py::self);

  py::bind_vector<broker::vector>(m, "Vector");

  py::class_<broker::data> data_type{m, "Data"};
  data_type
    .def(py::init<>())
    .def(py::init<broker::data>())
    .def(py::init<broker::address>())
    .def(py::init<broker::boolean>())
    .def(py::init([](count_type c) {
         return broker::data{c.value};
         }))
    .def(py::init([](broker::enum_value e) {
         return broker::data{e};
         }))
    .def(py::init<broker::integer>())
    .def(py::init<broker::port>())
    .def(py::init<broker::real>())
    .def(py::init<broker::set>())
    .def(py::init<std::string>())
    .def(py::init<broker::subnet>())
    .def(py::init<broker::table>())
    .def(py::init<broker::timespan>())
    .def(py::init<broker::timestamp>())
    .def(py::init<broker::vector>())
    .def("as_address", [](const broker::data& d) { return caf::get<broker::address>(d); })
    .def("as_boolean", [](const broker::data& d) { return caf::get<broker::boolean>(d); })
    .def("as_count", [](const broker::data& d) { return caf::get<broker::count>(d); })
    .def("as_enum_value", [](const broker::data& d) { return caf::get<broker::enum_value>(d); })
    .def("as_integer", [](const broker::data& d) { return caf::get<broker::integer>(d); })
    .def("as_none", [](const broker::data& d) { return caf::get<broker::none>(d); })
    .def("as_port", [](const broker::data& d) { return caf::get<broker::port>(d); })
    .def("as_real", [](const broker::data& d) { return caf::get<broker::real>(d); })
    .def("as_set", [](const broker::data& d) { return caf::get<broker::set>(d); })
    .def("as_string", [](const broker::data& d) { return py::bytes(caf::get<std::string>(d)); })
    .def("as_subnet", [](const broker::data& d) { return caf::get<broker::subnet>(d); })
    .def("as_table", [](const broker::data& d) { return caf::get<broker::table>(d); })
    .def("as_timespan", [](const broker::data& d) {
        double s;
        broker::convert(caf::get<broker::timespan>(d), s);
	return s;
	})
    .def("as_timestamp", [](const broker::data& d) {
        double s;
        broker::convert(caf::get<broker::timestamp>(d), s);
	return s;
	})
    .def("as_vector", [](const broker::data& d) { return caf::get<broker::vector>(d); })
    .def("get_type", &broker::data::get_type)
    .def("__str__", [](const broker::data& d) { return broker::to_string(d); })
    .def(py::self < py::self)
    .def(py::self <= py::self)
    .def(py::self > py::self)
    .def(py::self >= py::self)
    .def(py::self == py::self)
    .def(py::self != py::self);

  py::enum_<broker::data::type>(data_type, "Type")
    .value("Nil", broker::data::type::none)
    .value("Address", broker::data::type::address)
    .value("Boolean", broker::data::type::boolean)
    .value("Count", broker::data::type::count)
    .value("EnumValue", broker::data::type::enum_value)
    .value("Integer", broker::data::type::integer)
    .value("None", broker::data::type::none)
    .value("Port", broker::data::type::port)
    .value("Real", broker::data::type::real)
    .value("Set", broker::data::type::set)
    .value("String", broker::data::type::string)
    .value("Subnet", broker::data::type::subnet)
    .value("Table", broker::data::type::table)
    .value("Timespan", broker::data::type::timespan)
    .value("Timestamp", broker::data::type::timestamp)
    .value("Vector", broker::data::type::vector);
}

