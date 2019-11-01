
#include <utility>
#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <pybind11/pybind11.h>
#pragma GCC diagnostic pop

#include "broker/zeek.hh"
#include "broker/data.hh"

namespace py = pybind11;
using namespace pybind11::literals;

void init_zeek(py::module& m) {
  py::class_<broker::zeek::Message>(m, "Message")
    .def("as_data",
         static_cast<const broker::data& (broker::zeek::Message::*)() const>
         (&broker::zeek::Message::as_data));

  py::class_<broker::zeek::Event, broker::zeek::Message>(m, "Event")
    .def(py::init([](broker::data data) {
       return broker::zeek::Event(std::move(data));
       }))
    .def(py::init([](std::string name, broker::data args) {
       return broker::zeek::Event(std::move(name), std::move(caf::get<broker::vector>(args)));
       }))
    .def("name",
          static_cast<const std::string& (broker::zeek::Event::*)() const>
          (&broker::zeek::Event::name))
    .def("args",
         static_cast<const broker::vector& (broker::zeek::Event::*)() const>
         (&broker::zeek::Event::args));
}

