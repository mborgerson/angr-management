# FIXME: Support debugging target threads
# FIXME: Support launching with local GDB
# FIXME: Support analysis of remote GDB target, with access to files
#        - Files may be local, or files may be accessible via GDB
# FIXME: Support analysis of remote GDB target, without access to files
#        - Create blob loader, load code out of memory
# FIXME: Support disassembly on demand, without needing to download
#        big chunks.
# FIXME: Support CFG generation on demand. Shouldn't need to generate CFG for entire region, attempt current function.
# FIXME: Add option to update loaded modules (info proc mappings) at runtime. Desired modules may not be loaded by the
#        time we create the project. Maybe just check whenever we halt to see if new modules were loaded, then add them.
import functools
import subprocess
import logging
import os
import re
from tempfile import NamedTemporaryFile
from typing import Optional, Sequence

from PySide2.QtCore import QObject, Signal, Slot

import angr
from angr import SimState, SimulationManager
from angr_targets import ConcreteTarget, AvatarGDBConcreteTarget

import avatar2
from angrmanagement.data.jobs import SimgrStepJob, SimgrExploreJob
from angrmanagement.ui.widgets.qsimulation_managers import QSimulationManagers
from avatar2 import Avatar, GDBTarget, TargetStates
from cle.gdb import convert_info_proc_maps

from ..threads import gui_thread_schedule, gui_thread_schedule_async


_l = logging.getLogger(name=__name__)


class DebuggerWatcher(QObject):
    """
    Watcher object that automatically connects signals and calls callbacks.
    """

    def __init__(self, state_updated_callback, workspace: 'Workspace'):
        self.workspace = workspace
        self.state_updated_callback = state_updated_callback
        self._last_selected_debugger = None
        self.workspace.instance.debugger.am_subscribe(self._on_debugger_updated)
        self._on_debugger_updated()

    def _on_debugger_updated(self, *args, **kwargs):  # pylint:disable=unused-argument
        dbg = self._last_selected_debugger
        if dbg:
            dbg.state_changed.disconnect(self._on_debugger_state_updated)
            # dbg.simstate_changed.disconnect(self._on_debugger_state_updated)
            self._last_selected_debugger = None

        dbg = self.workspace.instance.debugger
        if not dbg.am_none:
            dbg.state_changed.connect(self._on_debugger_state_updated)
            # dbg.simstate_changed.connect(self._on_debugger_state_updated)
            self._last_selected_debugger = dbg.am_obj

        self._on_debugger_state_updated()

    def _on_debugger_state_updated(self):
        self.state_updated_callback()


class Debugger(QObject):
    """
    Provides a generic interface with common debugger operations to control program execution and inspect program state.
    """

    state_changed: Signal = Signal()
    simstate_changed: Signal = Signal()
    connect_failed: Signal = Signal()

    def __init__(self, workspace: 'Workspace'):
        super().__init__()
        self.workspace: 'Workspace' = workspace
        self.instance: 'Instance' = workspace.instance

    @property
    def state_description(self) -> str:
        """
        Get a string describing the current debugging state.
        """
        return ''

    def _move_disassembly_view_to_ip(self):
        """
        Jump to target PC in active disassembly view.
        """
        try:
            # FIXME: Instead of us controlling the disassembly view here, it would
            #        be preferred to allow the disassembly view to synchronize with a watcher.
            pc = self.simstate.solver.eval(self.simstate.regs.pc)
            if len(self.workspace.view_manager.views_by_category['disassembly']) == 1:
                disasm_view = self.workspace.view_manager.first_view_in_category('disassembly')
            else:
                disasm_view = self.workspace.view_manager.current_view_in_category('disassembly')

            if disasm_view is not None:
                disasm_view.jump_to(pc)
        except:
            pass

    def init(self):
        """
        Initialize target connection.
        """

    @property
    def is_running(self) -> bool:
        """
        Determine if target is running.
        """
        return False

    @property
    def can_step_backward(self) -> bool:
        """
        Determine if the target can step backward by one machine instruction.
        """
        return False

    def step_backward(self):
        """
        Step backward by one machine instruction.
        """
        raise NotImplementedError()

    @property
    def can_step_forward(self) -> bool:
        """
        Determine if the target can step forward by one machine instruction.
        """
        return False

    def step_forward(self):
        """
        Step forward by one machine instruction.
        """
        raise NotImplementedError()

    @property
    def can_continue_backward(self) -> bool:
        """
        Determine if execution can continue in reverse.
        """
        return False

    def continue_backward(self):
        """
        Continue execution in reverse.
        """
        raise NotImplementedError()

    @property
    def can_continue_forward(self) -> bool:
        """
        Determine if execution can continue.
        """
        return False

    def continue_forward(self):
        """
        Continue execution.
        """
        raise NotImplementedError()

    @property
    def can_halt(self) -> bool:
        """
        Determine if the target can be interrupted.
        """
        return False

    def halt(self):
        """
        Interrupt the target.
        """
        raise NotImplementedError()

    @property
    def is_halted(self) -> bool:
        """
        Determine if the target has been interrupted and is now halted.
        """
        return False

    @property
    def can_stop(self) -> bool:
        """
        Determine if the target can be stopped.
        """
        return False

    def stop(self):
        """
        Stop the target.
        """
        raise NotImplementedError()

    @property
    def is_exited(self) -> bool:
        """
        Determine if the target has exited.
        """
        return False
