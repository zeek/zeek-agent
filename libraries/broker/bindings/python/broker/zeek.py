
try:
    from . import _broker
except ImportError:
    import _broker

import broker

class Event(_broker.zeek.Event):
    def __init__(self, *args):
        if len(args) == 1 and not isinstance(args[0], str):
            # Parse raw broker message as event.
            _broker.zeek.Event.__init__(self, broker.Data.from_py(args[0]))
        else:
            # (name, arg1, arg2, ...)
            _broker.zeek.Event.__init__(self, args[0], broker.Data.from_py(args[1:]))

    def args(self):
        return [broker.Data.to_py(a) for a in _broker.zeek.Event.args(self)]
