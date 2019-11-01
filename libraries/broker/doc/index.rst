Broker User Manual
==================

**Broker** is a library for type-rich publish/subscribe communication in
`Zeek <https://www.zeek.org>`_'s data model.

Outline
--------

:ref:`overview` introduces Broker's key components and basic terminology,
such as *endpoints*, *messages*, *topics*, and *data stores*.

:ref:`communication` shows how one can send and receive data with Broker's
publish/subscribe communication primitives. By structuring applications in
independent *endpoints* and peering with other endpoints, one can create a
variety of different communication topologies that perform topic-based message
routing.

:ref:`data-model` presents Broker's data model, which applications can
pack into messages and publish under given topics. The same data model
is also used by Broker's :ref:`data stores <data-stores>`.

:ref:`data-stores` introduces *data stores*, a distributed key-value
abstraction operating with the complete :ref:`data model
<data-model>`, for both keys and values. Users interact with a data
store *frontend*, which is either an authoritative *master* or a
*clone* replica. The master can choose to keep its data in various
*backends*, currently either in-memory, or persistently through
`SQLite <https://www.sqlite.org>`_, or `RocksDB
<http://rocksdb.org>`_.

:ref:`python` discusses the Broker's Python bindings, which
transparently expose all of the library's functionality to Python
scripts. 

Synopsis
--------

.. literalinclude:: _examples/synopsis.cc

.. toctree::
  :numbered:
  :hidden:

  overview
  comm
  data
  stores
  python
