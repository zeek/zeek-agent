from __future__ import print_function

from . import zeek

import traceback
import sys

class Event(zeek.Event):

    warnings_emitted = set()

    def __new__(cls, *args, **kwargs):
        stack_info = traceback.extract_stack()[0]
        usage_file = stack_info[0]
        usage_line = stack_info[1]
        usage_text = stack_info[3]

        if (usage_file, usage_line) not in Event.warnings_emitted:
            print('File "{}", line {}: deprecated bro.event usage,'
                  ' use zeek.Event instead:\n    {}'.format(
                      usage_file, usage_line, usage_text),
                  file=sys.stderr)

            Event.warnings_emitted.add((usage_file, usage_line))

        return super(Event, cls).__new__(cls, *args, **kwargs)
