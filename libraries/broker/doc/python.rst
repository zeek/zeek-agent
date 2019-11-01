
.. _python:

Python Bindings
===============

Almost all functionality of Broker is also accessible through Python
bindings. The Python API mostly mimics the C++ interface, but adds
transparent conversion between Python values and Broker values. In the
following we demonstrate the main parts of the Python API, assuming a
general understanding of Broker's concepts and the C++ interface.

.. note:: Broker's Python bindings require Python 2.7 or Python 3.  If you
    are using Python 2.7, then you will need to install
    the `ipaddress <https://pypi.python.org/pypi/ipaddress>`_ module from
    PyPI (one way to do this is to run "pip install ipaddress").

Installation in a Virtual Environment
-------------------------------------

To install Broker's python bindings in a virtual environment, the
**python-prefix** configuration option can be specified and the python
header files must be on the system for the version of python in the
virtual environment.  You can also use the **prefix** configuration
option to install the main Broker library and headers into an isolated
location.

.. code-block:: bash

    $ virtualenv -p python3 /Users/user/sandbox/broker/venv
    $ . /Users/user/sandbox/broker/venv/bin/activate
    $ ./configure --prefix=/Users/user/sandbox/broker --python-prefix=$(python -c 'import sys; print(sys.exec_prefix)')
    $ make install
    $ python -c 'import broker; print(broker.__file__)'
    /Users/user/sandbox/broker/venv/lib/python3.7/site-packages/broker/__init__.py

Communication
-------------

Just as in C++, you first set up peerings between endpoints and
create subscriber for the topics of interest:

.. literalinclude:: ../tests/python/communication.py
   :language: python
   :start-after: --peer-start
   :end-before: --peer-end

You can then start publishing messages. In Python a message is just
a list of values, along with the corresponding topic.
The following publishes a simple message consisting of just one
string, and then has the receiving endpoint wait for it to arrive:

.. literalinclude:: ../tests/python/communication.py
   :language: python
   :start-after: --ping-start
   :end-before: --ping-end

Example of publishing a small batch of two slightly more complex
messages with two separate topics:

.. literalinclude:: ../tests/python/communication.py
   :language: python
   :start-after: --messages-start
   :end-before: --messages-end

As you see with the 2nd message there, elements can be either standard
Python values or instances of Broker wrapper classes; see the data
model section below for more.

The subscriber instances have more methods matching their C++
equivalent, including ``available`` for checking for pending messages,
``poll()`` for getting available messages without blocking, ``fd()``
for retrieving a select-able file descriptor, and ``{add,remove}_topic``
for changing the subscription list.

Exchanging Zeek Events
----------------------

The Broker Python bindings come with support for representing Zeek
events as well. Here's the Python version of the :ref:`C++ ping example
shown earlier <zeek_events_cpp>`:

.. literalinclude:: _examples/ping.zeek

.. literalinclude:: _examples/ping.py

.. code-block:: bash

    # python3 ping.py
    received pong[0]
    received pong[1]
    received pong[2]
    received pong[3]
    received pong[4]

Data Model
----------

The Python API can represent the same type model as the C++ code. For
all Broker types that have a direct mapping to a Python type,
conversion is handled transparently as values are passed into, or
retrieved from, Broker.  For example, the message ``[1, 2, 3]`` above
is automatically converted into a Broker list of three Broker integer
values. In cases where there is not a direct Python equivalent for a
Broker type (e.g., for ``count``; Python does not have an unsigned
integer class), the Broker module provides wrapper classes. The
following table summarizes how Broker and Python values are mapped to
each other:

.. list-table::
   :header-rows: 1

   * - Broker Type
     - Python representation
   * - ``boolean``
     - ``True``/``False``
   * - ``count``
     - ``broker.Count(x)``
   * - ``integer``
     - ``int``
   * - ``real``
     - ``float``
   * - ``timespan``
     - ``datetime.timedelta``
   * - ``timestamp``
     - ``datetime.datetime``
   * - ``string``
     - ``str``
   * - ``address``
     - ``ipaddress.IPv4Address``/``ipaddress.IPv6Address``
   * - ``subnet``
     - ``ipaddress.IPv4Network``/``ipaddress.IPv6Network``
   * - ``port``
     - ``broker.Port(x, broker.Port.{TCP,UDP,ICMP,Unknown})``
   * - ``vector``
     - ``tuple``
   * - ``set``
     - ``set``
   * - ``table``
     - ``dict``

Note that either a Python ``tuple`` or Python ``list`` may convert
to a Broker ``vector``, but the canonical Python type representing
a ``vector`` is a tuple.  That is, whenever converting a Broker
``vector`` value into a Python value, you will get a ``tuple``.
A ``tuple`` is the canonical type here because it is an immutable type,
but a ``list`` is mutable --  we need to be able to represent tables
indexed by vectors, tables are mapped to Python dictionaries, Python
dictionaries only allow immutable index types, and so we must use a
``tuple`` to represent a ``vector``.

Status and Error Messages
-------------------------

Status and error handling works through a status subscriber, again
similar to the C++ interface:

.. literalinclude:: ../tests/python/communication.py
   :language: python
   :start-after: --error-start
   :lines: 1-3,5-6
   :end-before: --error-end

.. literalinclude:: ../tests/python/communication.py
   :language: python
   :start-after: --status-start
   :end-before: --status-end

Data Stores
-----------

For data stores, the C++ API also directly maps to Python. The
following instantiates a master store to then operate on:

.. literalinclude:: ../tests/python/store.py
   :language: python
   :start-after: --master-start
   :end-before: --master-end

In Python, both master and clone stores provide all the same accessor
and mutator methods as C++. Some examples:

.. literalinclude:: ../tests/python/store.py
   :language: python
   :start-after: --ops-start
   :end-before: --ops-end



