import os

from angr import SimState
from bintrace.debugger_angr import *

from .debugger import Debugger


_l = logging.getLogger(name=__name__)


class BintraceDebugger(Debugger):
    """
    Trace playback debugger.
    """

    def __init__(self, trace_mgr: TraceManager, workspace: 'Workspace'):
        super().__init__(workspace)
        self._trace_mgr: TraceManager = trace_mgr
        self._trace_dbg: AngrTraceDebugger = AngrTraceDebugger(self._trace_mgr, self.workspace.instance.project)
        self._cached_simstate = None

    def __str__(self):
        pc = self.simstate.solver.eval(self.simstate.regs.pc)
        return f'{os.path.basename(self._trace_mgr.path)} @ {pc:x}'

    def _on_state_change(self):
        """
        Common handler for state changes.
        """
        self._cached_simstate = None
        self.state_changed.emit()
        self.simstate_changed.emit()
        self._move_disassembly_view_to_ip()

    def _sync_breakpoints(self):
        """
        Synchronize breakpoints set in Workspace with trace debugger.
        """
        self._trace_dbg.breakpoints = self.workspace.breakpoints

    @property
    def simstate(self) -> SimState:
        if self._cached_simstate is None:
            self._cached_simstate = self._trace_dbg.simstate
        return self._cached_simstate

    @property
    def is_running(self) -> bool:
        return True

    @property
    def can_step_backward(self) -> bool:
        return self._trace_dbg.can_step_backward

    def step_backward(self):
        if self.can_step_backward:
            self._trace_dbg.step_backward()
            self._on_state_change()

    @property
    def can_step_forward(self) -> bool:
        return self._trace_dbg.can_step_forward

    def step_forward(self):
        if self.can_step_forward:
            self._trace_dbg.step_forward()
            self._on_state_change()

    @property
    def can_continue_backward(self) -> bool:
        return self._trace_dbg.can_continue_backward

    def continue_backward(self):
        if self.can_continue_backward:
            self._sync_breakpoints()
            self._trace_dbg.continue_backward()
            self._on_state_change()

    @property
    def can_continue_forward(self) -> bool:
        return self._trace_dbg.can_continue_forward

    def continue_forward(self):
        if self.can_continue_forward:
            self._sync_breakpoints()
            self._trace_dbg.continue_forward()
            self._on_state_change()

    @property
    def can_halt(self) -> bool:
        return False  # XXX: Trace playback is "instantaneous", always is halted state.

    @property
    def is_halted(self) -> bool:
        return True

    @property
    def can_stop(self) -> bool:
        return True

    def stop(self):
        if self.can_stop:
            self.workspace.instance.remove_debugger(self)

    @property
    def is_exited(self) -> bool:
        return False
