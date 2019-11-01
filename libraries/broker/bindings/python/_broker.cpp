
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <string>
#include <utility>
#include <vector>

#include <caf/variant.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <pybind11/functional.h>
#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl_bind.h>
#pragma GCC diagnostic pop

#include "broker/backend.hh"
#include "broker/backend_options.hh"
#include "broker/configuration.hh"
#include "broker/convert.hh"
#include "broker/data.hh"
#include "broker/detail/shared_queue.hh"
#include "broker/endpoint.hh"
#include "broker/endpoint_info.hh"
#include "broker/network_info.hh"
#include "broker/peer_flags.hh"
#include "broker/peer_info.hh"
#include "broker/peer_status.hh"
#include "broker/publisher.hh"
#include "broker/status.hh"
#include "broker/status_subscriber.hh"
#include "broker/store.hh"
#include "broker/subscriber.hh"
#include "broker/subscriber_base.hh"
#include "broker/time.hh"
#include "broker/topic.hh"
#include "broker/version.hh"

#include <memory>

namespace py = pybind11;

extern void init_zeek(py::module& m);
extern void init_data(py::module& m);
extern void init_enums(py::module& m);
extern void init_store(py::module& m);

PYBIND11_MAKE_OPAQUE(broker::set)
PYBIND11_MAKE_OPAQUE(broker::table)
PYBIND11_MAKE_OPAQUE(broker::vector)

PYBIND11_MODULE(_broker, m) {
  m.doc() = "Broker python bindings";
  py::module mb = m.def_submodule("zeek", "Zeek-specific bindings");

  init_zeek(mb);
  init_enums(m);
  init_data(m);
  init_store(m);

  auto version = m.def_submodule("Version", "Version constants");
  version.attr("MAJOR")
    = py::cast(new broker::version::type{broker::version::major});
  version.attr("MINOR")
    = py::cast(new broker::version::type{broker::version::minor});
  version.attr("PATCH")
    = py::cast(new broker::version::type{broker::version::patch});
  version.attr("PROTOCOL")
    = py::cast(new broker::version::type{broker::version::protocol});
  version.def("compatible", &broker::version::compatible,
              "Checks whether two Broker protocol versions are compatible");

  m.def("now", &broker::now, "Get the current wallclock time");

  py::class_<broker::endpoint_info>(m, "EndpointInfo")
    // TODO: Can we convert this optional<network_info> directly into network_info or None?
    .def_readwrite("network", &broker::endpoint_info::network)
    .def("node_id", [](const broker::endpoint_info& e) { return to_string(e.node); })
    .def("__repr__", [](const broker::endpoint_info& e) { return to_string(e.node); });

  py::class_<broker::network_info>(m, "NetworkInfo")
    .def_readwrite("address", &broker::network_info::address)
    .def_readwrite("port", &broker::network_info::port)
    .def("__repr__", [](const broker::network_info& n) { return to_string(n); });

  py::class_<broker::optional<broker::network_info>>(m, "OptionalNetworkInfo")
    .def("is_set",
         [](broker::optional<broker::network_info>& i) { return static_cast<bool>(i);})
    .def("get",
         [](broker::optional<broker::network_info>& i) { return *i; })
    .def("__repr__", [](const broker::optional<broker::network_info>& i) { return to_string(i); });

  py::class_<broker::peer_info>(m, "PeerInfo")
    .def_readwrite("peer", &broker::peer_info::peer)
    .def_readwrite("flags", &broker::peer_info::flags)
    .def_readwrite("status", &broker::peer_info::status);

  py::bind_vector<std::vector<broker::peer_info>>(m, "VectorPeerInfo");

  py::class_<broker::topic>(m, "Topic")
    .def(py::init<std::string>())
    .def(py::self /= py::self,
         "Appends a topic component with a separator")
    .def(py::self / py::self,
         "Appends topic components with a separator")
    .def("string", &broker::topic::string,
         "Get the underlying string representation of the topic",
         py::return_value_policy::reference_internal)
    .def("__repr__", [](const broker::topic& t) { return t.string(); });

  py::bind_vector<std::vector<broker::topic>>(m, "VectorTopic");

  py::class_<broker::infinite_t>(m, "Infinite")
    .def(py::init<>());

  py::class_<broker::publisher>(m, "Publisher")
    .def("demand", &broker::publisher::demand)
    .def("buffered", &broker::publisher::buffered)
    .def("capacity", &broker::publisher::capacity)
    .def("free_capacity", &broker::publisher::free_capacity)
    .def("send_rate", &broker::publisher::send_rate)
    .def("fd", &broker::publisher::fd)
    .def("drop_all_on_destruction", &broker::publisher::drop_all_on_destruction)
    .def("publish", (void (broker::publisher::*)(broker::data d)) &broker::publisher::publish)
    .def("publish_batch",
       [](broker::publisher& p, std::vector<broker::data> xs) { p.publish(xs); });

  using subscriber_base = broker::subscriber_base<broker::subscriber::value_type>;
  using topic_data_pair = std::pair<broker::topic, broker::data>;

  py::bind_vector<std::vector<topic_data_pair>>(m, "VectorPairTopicData");

  py::class_<broker::optional<topic_data_pair>>(m, "OptionalSubscriberBaseValueType")
    .def("is_set",
         [](broker::optional<topic_data_pair>& i) { return static_cast<bool>(i);})
    .def("get",
         [](broker::optional<topic_data_pair>& i) { return *i; })
    .def("__repr__", [](const broker::optional<topic_data_pair>& i) { return to_string(i); });

  py::class_<subscriber_base>(m, "SubscriberBase")
    .def("get",
         [](subscriber_base& ep) -> topic_data_pair {
       auto res = ep.get();
       return std::make_pair(broker::get_topic(res), broker::get_data(res));
      })

    .def("get",
         [](subscriber_base& ep, double secs) -> broker::optional<topic_data_pair> {
	    auto res = ep.get(broker::to_duration(secs));
        caf::optional<topic_data_pair> rval;
        if (res) {
          auto p = std::make_pair(broker::get_topic(*res), broker::get_data(*res));
          rval = caf::optional<topic_data_pair>(std::move(p));
        }
        return rval;
	  })

    .def("get",
         [](subscriber_base& ep, size_t num) -> std::vector<topic_data_pair> {
	   auto res = ep.get(num);
       std::vector<topic_data_pair> rval;
       rval.reserve(res.size());
       for ( auto& e : res )
         rval.emplace_back(std::make_pair(broker::get_topic(e), broker::get_data(e)));
       return rval;
      })

    .def("get",
         [](subscriber_base& ep, size_t num, double secs) -> std::vector<topic_data_pair> {
	   auto res = ep.get(num, broker::to_duration(secs));
       std::vector<topic_data_pair> rval;
       rval.reserve(res.size());
       for ( auto& e : res )
         rval.emplace_back(std::make_pair(broker::get_topic(e), broker::get_data(e)));
       return rval;
	  })

    .def("poll", &subscriber_base::poll)
    .def("available", &subscriber_base::available)
    .def("fd", &subscriber_base::fd);

  py::class_<broker::subscriber, subscriber_base>(m, "Subscriber")
    .def("add_topic", &broker::subscriber::add_topic)
    .def("remove_topic", &broker::subscriber::remove_topic);

  using status_subscriber_base = broker::subscriber_base<broker::status_subscriber::value_type>;

  py::bind_vector<std::vector<status_subscriber_base::value_type>>(m, "VectorStatusSubscriberValueType");

  py::class_<status_subscriber_base>(m, "StatusSubscriberBase")
    .def("get", (status_subscriber_base::value_type (status_subscriber_base::*)()) &status_subscriber_base::get)
    .def("get",
         [](status_subscriber_base& ep, double secs) -> broker::optional<status_subscriber_base::value_type> {
	   return ep.get(broker::to_duration(secs)); })
    .def("get",
         [](status_subscriber_base& ep, size_t num) -> std::vector<status_subscriber_base::value_type> {
	   return ep.get(num); })
    .def("get",
         [](status_subscriber_base& ep, size_t num, double secs) -> std::vector<status_subscriber_base::value_type> {
	   return ep.get(num, broker::to_duration(secs)); })
    .def("poll",
         [](status_subscriber_base& ep) -> std::vector<status_subscriber_base::value_type> {
	   return ep.poll(); })
    .def("available", &status_subscriber_base::available)
    .def("fd", &status_subscriber_base::fd);

  py::class_<broker::status>(m, "Status")
    .def(py::init<>())
    .def("code", &broker::status::code)
    .def("context", &broker::status::context<broker::endpoint_info>,
	 py::return_value_policy::reference_internal)
    .def("__repr__", [](const broker::status& s) { return to_string(s); });

  py::class_<broker::error>(m, "Error")
    .def(py::init<>())
    .def("code", &broker::error::code)
    .def("__repr__", [](const broker::error& e) { return to_string(e); });

  py::class_<broker::status_subscriber, status_subscriber_base> status_subscriber(m, "StatusSubscriber");

  py::class_<broker::status_subscriber::value_type>(status_subscriber, "ValueType")
    .def("is_error",
         [](broker::status_subscriber::value_type& x) -> bool { return caf::holds_alternative<broker::error>(x);})
    .def("is_status",
         [](broker::status_subscriber::value_type& x) -> bool { return caf::holds_alternative<broker::status>(x);})
    .def("get_error",
         [](broker::status_subscriber::value_type& x) -> broker::error { return caf::get<broker::error>(x);})
    .def("get_status",
         [](broker::status_subscriber::value_type& x) -> broker::status { return caf::get<broker::status>(x);});

  py::bind_map<broker::backend_options>(m, "MapBackendOptions");

  py::class_<broker::broker_options>(m, "BrokerOptions")
    .def(py::init<>())
    .def_readwrite("disable_ssl", &broker::broker_options::disable_ssl)
    .def_readwrite("ttl", &broker::broker_options::ttl)
    .def_readwrite("forward", &broker::broker_options::forward)
    .def_readwrite("use_real_time", &broker::broker_options::use_real_time);

  // We need a configuration class here that's separate from
  // broker::configuration. When creating an endpoint one has to instantiate
  // the standard class right at that point, one cannot pass an already
  // created one in, which is unfortunate.
  struct Configuration {
    Configuration() {};
    Configuration(broker::broker_options opts) : options(std::move(opts)) {}
    broker::broker_options options = {};
    std::string openssl_cafile;
    std::string openssl_capath;
    std::string openssl_certificate;
    std::string openssl_key;
    std::string openssl_passphrase;
    int max_threads = 0;
  };

  py::class_<Configuration>(m, "Configuration")
    .def(py::init<>())
    .def(py::init<broker::broker_options>())
    .def_readwrite("openssl_cafile", &Configuration::openssl_cafile)
    .def_readwrite("openssl_capath", &Configuration::openssl_capath)
    .def_readwrite("openssl_certificate", &Configuration::openssl_certificate)
    .def_readwrite("openssl_key", &Configuration::openssl_key)
    .def_readwrite("openssl_passphrase", &Configuration::openssl_passphrase)
    .def_readwrite("max_threads", &Configuration::max_threads);

  py::class_<broker::endpoint>(m, "Endpoint")
    .def(py::init<>())
    .def(py::init([](Configuration cfg) {
        broker::configuration bcfg(cfg.options);
        bcfg.openssl_capath = cfg.openssl_capath;
        bcfg.openssl_passphrase = cfg.openssl_passphrase;
        bcfg.openssl_cafile = cfg.openssl_cafile;
        bcfg.openssl_certificate = cfg.openssl_certificate;
        bcfg.openssl_key = cfg.openssl_key;
        if ( cfg.max_threads > 0 )
          bcfg.set("scheduler.max-threads", cfg.max_threads);
        return std::unique_ptr<broker::endpoint>(new broker::endpoint(std::move(bcfg)));
        }))
    .def("__repr__", [](const broker::endpoint& e) { return to_string(e.node_id()); })
    .def("node_id", [](const broker::endpoint& e) { return to_string(e.node_id()); })
    .def("listen", &broker::endpoint::listen, py::arg("address"), py::arg("port") = 0)
    .def("peer",
         [](broker::endpoint& ep, std::string& addr, uint16_t port, double retry) -> bool {
	 return ep.peer(addr, port, std::chrono::seconds((int)retry));},
         py::arg("addr"), py::arg("port"), py::arg("retry") = 10.0
         )
    .def("peer_nosync",
         [](broker::endpoint& ep, std::string& addr, uint16_t port, double retry) {
	 ep.peer_nosync(addr, port, std::chrono::seconds((int)retry));},
         py::arg("addr"), py::arg("port"), py::arg("retry") = 10.0
         )
    .def("unpeer", &broker::endpoint::unpeer)
    .def("unpeer_nosync", &broker::endpoint::unpeer_nosync)
    .def("peers", &broker::endpoint::peers)
    .def("peer_subscriptions", &broker::endpoint::peer_subscriptions)
    .def("forward", &broker::endpoint::forward)
    .def("publish", (void (broker::endpoint::*)(broker::topic t, broker::data d)) &broker::endpoint::publish)
    .def("publish", (void (broker::endpoint::*)(const broker::endpoint_info& dst, broker::topic t, broker::data d)) &broker::endpoint::publish)
    .def("publish_batch",
       [](broker::endpoint& ep, std::vector<topic_data_pair> batch) {
         std::vector<broker::data_message> xs;
         xs.reserve(batch.size());
         for ( auto& m : batch )
           xs.emplace_back(std::move(m.first), std::move(m.second));
         ep.publish(std::move(xs));
       })
    .def("make_publisher", &broker::endpoint::make_publisher)
    .def("make_subscriber", &broker::endpoint::make_subscriber, py::arg("topics"), py::arg("max_qsize") = 20)
    .def("make_status_subscriber", &broker::endpoint::make_status_subscriber, py::arg("receive_statuses") = false)
    .def("shutdown", &broker::endpoint::shutdown)
    .def("attach_master",
         [](broker::endpoint& ep, const std::string& name, broker::backend type,
            const broker::backend_options& opts) -> broker::expected<broker::store> {
	        return ep.attach_master(name, type, opts);
	    })
    .def("attach_clone",
         [](broker::endpoint& ep, const std::string& name) -> broker::expected<broker::store> {
	        return ep.attach_clone(name);
	    })
   ;
}

