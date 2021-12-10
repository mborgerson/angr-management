from typing import Set


class Trace:
    """
    Trace
    """


class TraceManager:
    """
    Manages all traces
    """

    def __init__(self):
        self.traces = set()

    def add_trace(self, trace: Trace):
        self.traces.add(trace)

    def remove_trace(self, trace: Trace):
        self.traces.remove(trace)
