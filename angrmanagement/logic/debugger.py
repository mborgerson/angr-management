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

from .threads import gui_thread_schedule, gui_thread_schedule_async

from bintrace import *
from bintrace.debugger import *
from bintrace.debugger_angr import *

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
    Provides a generic interface for controlling program execution.
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
            #        be preferred to allow the disassembly view to synchronize with
            #        RIP.
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


class SimulationDebugger(Debugger):
    """
    Simulation debugger.
    """

    def __init__(self, sim_mgrs: QSimulationManagers, workspace: 'Workspace'):
        super().__init__(workspace)
        self._sim_mgr_view: QSimulationManagers = sim_mgrs
        self._sim_mgr = sim_mgrs.simgr
        self._sim_mgr.am_subscribe(self._watch_simgr)
        self._sim_mgr_view.state.am_subscribe(self._watch_state)

    def __str__(self):
        if self._sim_mgr.am_none:
            return 'No Simulation Manager'
        if self.simstate is None:
            return 'Simulation (No active states)'
        else:
            pc = self.simstate.solver.eval(self.simstate.regs.pc)
            return f'Simulation @ {pc:x} ({len(self._sim_mgr.stashes["active"])} active)'

    def _watch_state(self, **kwargs):
        self._on_state_change()

    def _watch_simgr(self, **kwargs):
        self._on_state_change()

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
        if not self._sim_mgr_view.state.am_none:
            return self._sim_mgr_view.state.am_obj
        elif len(self._sim_mgr.stashes["active"]) > 0:
            return self._sim_mgr.stashes["active"][0]
        else:
            return None

    @property
    def is_running(self) -> bool:
        return not self._sim_mgr.am_none

    @property
    def can_step_forward(self) -> bool:
        return not self._sim_mgr.am_none and self.is_halted and len(self._sim_mgr.stashes['active']) > 0

    def step_forward(self):
        if self.can_step_forward:
            self._sim_mgr_view._on_step_clicked()

    @property
    def can_continue_forward(self) -> bool:
        return self.can_step_forward

    def continue_forward(self):
        if self.can_continue_forward:
            self._sim_mgr_view._on_explore_clicked()

    @property
    def _num_active_explore_jobs(self) -> int:
        return functools.reduce(lambda s, j: s + isinstance(j, SimgrExploreJob), self.instance.jobs, 0)

    @property
    def is_halted(self) -> bool:
        return self._num_active_explore_jobs == 0

    @property
    def can_halt(self) -> bool:
        return not self.is_halted

    def halt(self):
        for job in self.instance.jobs:
            if isinstance(job, SimgrExploreJob):
                job.keyboard_interrupt()


class AvatarGdbDebugger(Debugger):
    """
    Interface to Avatar2's GDB target.
    """

    state_changed: Signal = Signal()
    simstate_changed: Signal = Signal()
    connect_failed: Signal = Signal()

    def __init__(self, workspace,
                 remote_host: str = '127.0.0.1', remote_port: int = 3333,
                 local_binary_command: Optional[Sequence[str]] = None
                 ):
        super().__init__()
        self.workspace: 'Workspace' = workspace

        self._local: bool = True
        self._remote_host: str = remote_host
        self._remote_port: int = remote_port
        self._target_path: str = ''

        self._connecting: bool = False
        self._run_state: TargetStates = None
        self._running: bool = True
        self._halted: bool = False

        self._state_dirty: bool = True
        self.realtime_simstate: SimState = None
        self.simstate: SimState = None

        self.avatar: Avatar = None
        self.angr_target: 'ConcreteTarget' = None
        self.project: angr.Project = None
        self.target: GDBTarget = None
        self.proc: subprocess.Popen = None

    @property
    def state_description(self) -> str:
        """
        Get a string describing the current debugging state.
        """
        if self._connecting:
            return 'Connecting...'
        return {
            TargetStates.CREATED: 'Created',
            TargetStates.INITIALIZED: 'Initialized',
            TargetStates.STOPPED: 'Stopped',
            TargetStates.RUNNING: 'Running',
            TargetStates.SYNCING: 'Syncing',
            TargetStates.EXITED: 'Exited',
            TargetStates.NOT_RUNNING: 'Not Running',
            TargetStates.BREAKPOINT: 'Breakpoint',
        }.get(self._run_state, '')

    def _on_target_state_update(self, *args, **kwargs):  # pylint:disable=unused-argument
        """
        Called from Avatar notification thread. Queue notification event on debugger event loop.
        """
        avatar, state_msg = args
        new_state = state_msg.state
        # QMetaObject.invokeMethod(self, '_on_target_state_update_internal')
        # self._on_target_state_update_internal()
        gui_thread_schedule_async(lambda: self._on_target_state_update_internal(new_state))

    def _on_target_state_update_internal(self, new_state):
        """
        Handle target state updates.
        """
        self._run_state = new_state
        self._running = not bool(self._run_state & TargetStates.EXITED)
        self._halted = (self._run_state == TargetStates.STOPPED)  # XXX

        if self._halted and self.project is None:
            self._create_angr_project()

        self._state_dirty |= self._halted

        self.sync_state()
        self.state_changed.emit()

    def _create_angr_project(self):
        """
        Create a new project with memory map loaded from remote.
        """
        self.project = self._create_angr_project_internal()

        def callback():
            cfg_args = {
                'data_references': True,
                'cross_references': True,
            }
            variable_recovery_args = {
                'skip_signature_matched_functions': True,
            }
            self.workspace.instance._reset_containers()
            self.workspace.instance.project.am_obj = self.project
            self.workspace.instance.project.am_event(
                cfg_args=cfg_args,
                variable_recovery_args=variable_recovery_args)

        # gui_thread_schedule(callback, ())
        callback()

    def _create_angr_project_internal(self) -> angr.Project:
        # `gdb> info proc mappings`
        _, v = self.target.protocols.execution.get_mappings()

        # XXX: GDB sends newlines as \\n escape sequences. Avatar adds extra \n.
        #      Normalize to actual expected output.
        v = ''.join(v).replace('\n', '').replace('\\n', '\n')

        # XXX: CLE expects proc mapping in a text file
        if v.strip():
            f = NamedTemporaryFile(delete=False)
            f.write(v.encode('utf-8'))
            f.close()
            ld_opts = convert_info_proc_maps(f.name)
            os.unlink(f.name)

            # FIXME: This is fragile. Handle the cases when this can fail.
            _, v = self.target.protocols.execution.console_command('maint info program-spaces')
            v = bytes(v.replace('\n', ''), 'utf-8').decode('unicode_escape')
            fname = None
            for l in v.splitlines():
                m = re.match(r'\*? \d+\s+target:(.+)', l)
                if m:
                    fname = m.group(1).strip()
                    break
            assert (fname is not None)

            # Only load the main object for now
            for k in ('force_load_libs', 'lib_opts'):
                if k in ld_opts:
                    ld_opts.pop(k)
        else:
            _l.error('Failed to get mappings from info proc mappings command')

            auxv = {}
            _, v = self.target.protocols.execution.console_command('info auxv')
            v = bytes(v.replace('\n', ''), 'utf-8').decode('unicode_escape')
            for l in v.splitlines():
                l_s = l.split()
                if len(l_s) > 1:
                    auxv[l_s[1]] = l_s[-1]

            if 'AT_EXECFN' not in auxv or 'AT_PHDR' not in auxv:
                _l.error('Could not determine binary from "info auxv" command')
                raise Exception('Unable to determine target info from "info auxv"')

            fname = auxv['AT_EXECFN']
            if fname.startswith('"') and fname.endswith('"'):
                fname = fname[1:-1]
            base = int(auxv['AT_PHDR'], 0) - 0x40

            if not os.path.exists(fname):
                _l.error('Could not find file "%s"', fname)
                # FIXME: Prompt to select binary
                raise Exception('Unable to open target binary')

            ld_opts = {'main_opts': {'base_addr': base}, 'auto_load_libs': False}

            # FIXME: If we cannot load the binary locally, or fetch it from the remote,
            #        then we should support loading it by reading it from memory.

        self._target_path = fname
        _l.info('Filename: %s', fname)
        ld_opts['auto_load_libs'] = False
        _l.info('Load options: %s', str(ld_opts))

        return angr.Project(self._target_path, load_options=ld_opts, concrete_target=self.angr_target)

    def init(self):
        """
        Launch/connect to target process.
        """
        try:
            # Avatar runs async event loop on a thread. When an event is received in the Avatar event loop, it
            # dispatches the event to one of its handler methods. 'Watchmen' system uses decorators around these methods
            # to invoke callbacks. Watchmen decorator calls any registered handlers. Add a handler here to catch state
            # changes and emit a signal to update UI state.
            #
            # XXX: The state change notification comes in asynchronously. When the signal is emitted, the UI thread
            # which has connected to the signal will get an event put in its queue to call the handler. The state is
            # subject to change before or during the handler ever runs. Think more about sync.

            self._connecting = True
            self.state_changed.emit()
            self.avatar = Avatar(arch=avatar2.archs.x86.X86_64, configure_logging=False)  # FIXME: Arch
            self.avatar.watchmen.add_watchman('UpdateState', 'after', self._on_target_state_update)
            self.target = self.avatar.add_target(GDBTarget, gdb_executable="gdb-multiarch",
                                                 gdb_ip=self._remote_host, gdb_port=self._remote_port)
            self.angr_target = DebuggerAvatarGDBConcreteTarget(self.avatar, self.target)
            self.avatar.init_targets()  # Connect

        except Exception as e:  # pylint:disable=broad-except
            _l.error(e)
            self._run_state = TargetStates.EXITED
            self.connect_failed.emit()

        self._connecting = False
        self._on_target_state_update_internal(self.target.get_status()['state'])

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def can_step_forward(self) -> bool:
        return self._halted

    def step_forward(self):
        self.target.step()

    def _synchronize_breakpoints(self):
        """
        Synchronize workspace breakpoints on target before running.
        """
        for addr in self.workspace.breakpoints:
            if addr not in self.breakpoints:
                self.breakpoints[addr] = self.target.set_breakpoint(f'*{addr:#x}')

        for addr in self.breakpoints:
            if addr not in self.workspace.breakpoints:
                self.target.remove_breakpoint(self.breakpoints.pop(addr))

    @property
    def can_continue_forward(self) -> bool:
        return self._halted

    def continue_forward(self):
        self._synchronize_breakpoints()
        self.target.cont()

    @property
    def can_halt(self) -> bool:
        return not self._halted

    def halt(self):
        self.target.stop()

    @property
    def is_halted(self) -> bool:
        return self._halted

    @property
    def can_stop(self) -> bool:
        return self._running

    def stop(self):
        """
        Stop the target and end debugging.
        """
        self.avatar.shutdown()
        self._running = False
        self._run_state = TargetStates.EXITED
        self.simstate = None
        self.state_changed.emit()
        if self.proc is not None:
            self.proc.kill()
            self.proc = None

    @property
    def is_exited(self) -> bool:
        return self._run_state == TargetStates.EXITED

    def sync_state(self):
        """
        Synchronize cached simstate accessible via property `simstate` with
        remote target. Runs whenever the target enters a stopped state.
        """
        if not self._state_dirty or self.target is None or self.project is None:
            return

        self.simstate = self.project.factory.blank_state(add_options={angr.options.FAST_MEMORY})

        for r in self.simstate.arch.register_list:
            if r.general_purpose:
                rval = self.target.read_register(r.name)
                if rval is None:
                    _l.error('Unavailable reg on target %s', r.name)
                    return
                setattr(self.simstate.regs, r.name, rval)

        self.realtime_simstate = self.simstate

        self.simstate_changed.emit()
        self._move_disassembly_view_to_ip()
        self._state_dirty = False


'''

class AvatarGdbDebugger(QObject):
    """
    Interface to Avatar2's GDB target.
    """

    state_changed: Signal = Signal()
    simstate_changed: Signal = Signal()
    connect_failed: Signal = Signal()

    def __init__(self, workspace,
                 remote_host: str = '127.0.0.1', remote_port: int = 3333,
                 local_binary_command: Optional[Sequence[str]] = None
                 ):
        super().__init__()
        self.workspace: 'Workspace' = workspace

        self._local: bool = True
        self._remote_host: str = remote_host
        self._remote_port: int = remote_port
        self._target_path: str = ''

        self._connecting: bool = False
        self._run_state: TargetStates = None
        self._running: bool = True
        self._halted: bool = False

        self._state_dirty: bool = True
        self.realtime_simstate: SimState = None
        self.simstate: SimState = None

        self.avatar: Avatar = None
        self.angr_target: 'ConcreteTarget' = None
        self.project: angr.Project = None
        self.target: GDBTarget = None
        self.proc: subprocess.Popen = None

        self._local_binary_command = local_binary_command
        self._trace_manager = None
        self._trace_debugger = None
        self._in_trace: bool = False

        self.breakpoints = {}

    @property
    def state_description(self) -> str:
        """
        Get a string describing the current debugging state.
        """
        if self._connecting:
            return 'Connecting...'
        return {
            TargetStates.CREATED:     'Created',
            TargetStates.INITIALIZED: 'Initialized',
            TargetStates.STOPPED:     'Stopped',
            TargetStates.RUNNING:     'Running',
            TargetStates.SYNCING:     'Syncing',
            TargetStates.EXITED:      'Exited',
            TargetStates.NOT_RUNNING: 'Not Running',
            TargetStates.BREAKPOINT:  'Breakpoint',
        }.get(self._run_state, '')

    def _on_target_state_update(self, *args, **kwargs):  # pylint:disable=unused-argument
        """
        Called from Avatar notification thread. Queue notification event on debugger event loop.
        """
        avatar, state_msg = args
        new_state = state_msg.state
        # QMetaObject.invokeMethod(self, '_on_target_state_update_internal')
        # self._on_target_state_update_internal()
        gui_thread_schedule_async(lambda: self._on_target_state_update_internal(new_state))

    @Slot()
    def _on_target_state_update_internal(self, new_state):
        """
        Handle target state updates.
        """
        self._run_state = new_state
        self._running = not bool(self._run_state & TargetStates.EXITED)
        self._halted = (self._run_state == TargetStates.STOPPED) # XXX

        if self._halted and self.project is None:
            self._create_angr_project()

        self._state_dirty |= self._halted

        self.sync_state()
        self.state_changed.emit()

    def _move_disassembly_view_to_ip(self):
        """
        Jump to target PC in active disassembly view.
        """
        try:
            # FIXME: Instead of us controlling the disassembly view here, it would
            #        be preferred to allow the disassembly view to synchronize with
            #        RIP.
            pc = self.simstate.solver.eval(self.simstate.regs.pc)
            if len(self.workspace.view_manager.views_by_category['disassembly']) == 1:
                disasm_view = self.workspace.view_manager.first_view_in_category('disassembly')
            else:
                disasm_view = self.workspace.view_manager.current_view_in_category('disassembly')

            if disasm_view is not None:
                disasm_view.jump_to(pc)
        except:
            pass

    def _create_angr_project(self):
        """
        Create a new project with memory map loaded from remote.
        """
        self.project = self._create_angr_project_internal()

        def callback():
            cfg_args = {
                'data_references': True,
                'cross_references': True,
            }
            variable_recovery_args = {
                'skip_signature_matched_functions': True,
            }
            self.workspace.instance._reset_containers()
            self.workspace.instance.project.am_obj = self.project
            self.workspace.instance.project.am_event(
                cfg_args=cfg_args,
                variable_recovery_args=variable_recovery_args)
        #gui_thread_schedule(callback, ())
        callback()

    def _create_angr_project_internal(self) -> angr.Project:
        # `gdb> info proc mappings`
        _, v = self.target.protocols.execution.get_mappings()

        # XXX: GDB sends newlines as \\n escape sequences. Avatar adds extra \n.
        #      Normalize to actual expected output.
        v = ''.join(v).replace('\n', '').replace('\\n', '\n')

        # XXX: CLE expects proc mapping in a text file
        _l.error('mappings: ' + v)
        if v.strip():
            f = NamedTemporaryFile(delete=False)
            f.write(v.encode('utf-8'))
            f.close()
            ld_opts = convert_info_proc_maps(f.name)
            os.unlink(f.name)

            # FIXME: This is fragile. Handle the cases when this can fail.
            _, v = self.target.protocols.execution.console_command('maint info program-spaces')
            v = bytes(v.replace('\n', ''), 'utf-8').decode('unicode_escape')
            fname = None
            for l in v.splitlines():
                m = re.match(r'\*? \d+\s+target:(.+)', l)
                if m:
                    fname = m.group(1).strip()
                    break
            assert(fname is not None)

            # Only load the main object for now
            for k in ('force_load_libs', 'lib_opts'):
                if k in ld_opts:
                    ld_opts.pop(k)
        else:
            _l.error('Failed to get mappings from info proc mappings command')

            auxv = {}
            _, v = self.target.protocols.execution.console_command('info auxv')
            v = bytes(v.replace('\n', ''), 'utf-8').decode('unicode_escape')
            for l in v.splitlines():
                l_s = l.split()
                if len(l_s) > 1:
                    auxv[l_s[1]] = l_s[-1]

            if 'AT_EXECFN' not in auxv or 'AT_PHDR' not in auxv:
                _l.error('Could not determine binary from "info auxv" command')
                raise Exception('Unable to determine target info from "info auxv"')
            else:
                base = 0x4000000000
                fname = auxv['AT_EXECFN']
                if fname.startswith('"') and fname.endswith('"'):
                    fname = fname[1:-1]
                if auxv['AT_PHDR'] != '0x4000000040':
                    _l.error('Unexpected phdr base: %s', auxv['AT_PHDR'])
                    # raise Exception('Unexpected phdr base')
                    base = int(auxv['AT_PHDR'], 0) - 0x40

            if not os.path.exists(fname):
                _l.error('Could not find file "%s"', fname)
                # Prompt to select binary
                raise Exception('Unable to open target binary')

            ld_opts = {'main_opts': {'base_addr': base}, 'auto_load_libs': False}
            self.trace_path = fname + '.trace'

            if os.path.exists(self.trace_path):
                _l.info('Attempting to create project from trace file')

                try:
                    tm = TraceManager()
                    tm.load_trace(self.trace_path)
                    mappings = list(tm.filter_image_map())
                    main_binary = mappings[0]
                    libs = mappings[1:] if len(mappings) > 1 else []
                    lib_map = defaultdict(list)
                    for lib in libs:
                        lib_map[lib.Name().decode('utf-8')].append(lib)
                    for name in list(lib_map.keys()):
                        if name in (main_binary.Name().decode('utf-8'), '/etc/ld.so.cache'):
                            lib_map.pop(name)
                        elif not os.path.exists(os.path.realpath(name)):
                            _l.warning('Could not find binary %s', name)
                            lib_map.pop(name)
                        else:
                            # XXX: We simply take the lowest address as image base. Possibly failure.
                            lib_map[name] = min(lib_map[name], key=lambda l: l.Base())

                    self._target_path = main_binary.Name().decode('utf-8')
                    ld_opts = {'main_opts': {'base_addr': main_binary.Base()},
                               'auto_load_libs': False,
                               'force_load_libs': [os.path.realpath(name) for name in lib_map],
                               'lib_opts': {os.path.realpath(name): {'base_addr': lib.Base()} for name, lib in
                                            lib_map.items()},
                               }
                except Exception:
                    _l.error('Failed')



            # FIXME: If we cannot load the binary locally, or fetch it from the remote,
            #        then we should support loading it by reading it from memory.

        self._target_path = fname
        _l.info('Filename: %s', fname)
        ld_opts['auto_load_libs'] = False
        _l.info('Load options: %s', str(ld_opts))

        self._trace_manager = None
        self._trace_debugger = None
        return angr.Project(self._target_path, load_options=ld_opts, concrete_target=self.angr_target)

    @Slot()
    def init(self):
        """
        Launch/connect to target process.
        """
        try:
            #
            # Avatar runs async event loop on a thread. When an event is
            # received in the Avatar event loop, it dispatches the event to one
            # of its handler methods. 'Watchmen' system uses decorators around
            # these methods to invoke callbacks. Watchmen decorator calls any
            # registered handlers. Add a handler here to catch state changes and
            # emit a signal to update UI state.
            #
            # XXX: The state change notification comes in asynchronously. When
            # the signal is emitted, the UI thread which has connected to the
            # signal will get an event put in its queue to call the handler. The
            # state is subject to change before or during the handler ever runs.
            # Think more about sync.
            #
            self._connecting = True
            self.state_changed.emit()

            self.avatar = Avatar(arch=avatar2.archs.x86.X86_64, configure_logging=False)  # FIXME: Arch
            self.avatar.watchmen.add_watchman('UpdateState', 'after', self._on_target_state_update)

            # self._target_path = self.workspace.instance.project.filename
            # if self._local:
            #     self.target = self.avatar.add_target(GDBTarget,
            #         local_binary=self.workspace.instance.project.filename
            #         )

            #     cmd = ['gdbserver', f'{self._remote_host}:{self._remote_port}', self._target_path]
            #     _l.info('Launching target in gdbserver via %s', str(cmd))
            #     self.proc = subprocess.Popen(cmd)

            # FIXME: Support launching QEMU here directly. We need to be able to provide some kind
            # of console interface however, so for now expect that someone launches it remotely.

            self.target = self.avatar.add_target(GDBTarget, gdb_executable="gdb-multiarch",
                                                 gdb_ip=self._remote_host, gdb_port=self._remote_port)
            self.angr_target = DebuggerAvatarGDBConcreteTarget(self.avatar, self.target)
            self.avatar.init_targets()  # Connect

        except Exception as e:  # pylint:disable=broad-except
            _l.error(e)
            self._run_state = TargetStates.EXITED
            self.connect_failed.emit()

        self._connecting = False
        self._on_target_state_update_internal(self.target.get_status()['state'])

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def can_step_backward(self) -> bool:
        return self._halted and self._trace_debugger is not None and self._trace_debugger.can_step_backward

    @Slot()
    def step_backward(self):
        assert self._trace_debugger is not None and self._trace_debugger.can_step_backward
        self._trace_debugger.step_backward()
        self._in_trace = True
        self._sync_trace_state()

    @property
    def can_step_forward(self) -> bool:
        return self._halted

    @Slot()
    def step_forward(self):
        if self._in_trace:
            self._trace_debugger.step_forward()
            self._sync_trace_state()
        else:
            self.target.step()

    def _synchronize_trace_breakpoints(self):
        """
        Synchronize workspace breakpoints on target before running.
        """
        _l.info('Synchronizing breakpoints')
        if self._trace_debugger:
            self._trace_debugger.breakpoints = self.workspace.breakpoints

    def _synchronize_breakpoints(self):
        """
        Synchronize workspace breakpoints on target before running.
        """
        _l.info('Synchronizing breakpoints')
        for addr in self.workspace.breakpoints:
            if addr not in self.breakpoints:
                _l.info('-- Adding breakpoint at %x', addr)
                self.breakpoints[addr] = self.target.set_breakpoint(f'*{addr:#x}')

        for addr in self.breakpoints:
            if addr not in self.workspace.breakpoints:
                _l.info('-- Removing breakpoint at %x', addr)
                self.target.remove_breakpoint(self.breakpoints.pop(addr))

    @property
    def can_continue_backward(self) -> bool:
        return self._halted and self._trace_debugger is not None and self._trace_debugger.can_continue_backward

    @Slot()
    def continue_backward(self):
        assert self._trace_debugger is not None and self._trace_debugger.can_continue_backward
        self._synchronize_trace_breakpoints()
        self._trace_debugger.continue_backward()
        self._in_trace = True
        self._sync_trace_state()

    @property
    def can_continue_forward(self) -> bool:
        return self._halted

    @Slot()
    def continue_forward(self):
        if self._in_trace:
            self._synchronize_trace_breakpoints()
            self._trace_debugger.continue_forward()
            self._sync_trace_state()
        else:
            self._synchronize_breakpoints()
            self.target.cont()

    @property
    def can_halt(self) -> bool:
        return not self._halted

    @Slot()
    def halt(self):
        self.target.stop()

    @property
    def is_halted(self) -> bool:
        return self._halted

    @property
    def can_stop(self) -> bool:
        return self._running

    @Slot()
    def stop(self):
        """
        Stop the target and end debugging.
        """
        self.avatar.shutdown()
        self._running = False
        self._run_state = TargetStates.EXITED
        self.simstate = None
        self.state_changed.emit()
        if self.proc is not None:
            self.proc.kill()
            self.proc = None

    @property
    def is_exited(self) -> bool:
        return self._run_state == TargetStates.EXITED

    def load_trace(self):
        _l.info('Loading trace...')

        update = False#self._trace_manager is not None
        if not update:
            self._trace_manager = TraceManager()
        try:
            self._trace_manager.load_trace(self.trace_path)#, update)
            self._trace_debugger = AngrTraceDebugger(self._trace_manager, self.project)
        except FileNotFoundError:
            self._trace_manager = None
            self._trace_debugger = None
            return

        _l.info('Replaying trace...')
        self._trace_debugger.continue_forward()

        _l.info('Trace ready!')
        self._in_trace = False

    def _sync_trace_state(self):
        """
        Stepping through trace history.
        """
        if self._in_trace:
            if not self._trace_debugger.can_step_forward:
                self._in_trace = False

        if self._in_trace:
            self.simstate = self._trace_debugger.simstate
        else:
            self.simstate = self.realtime_simstate

        self.state_changed.emit()
        self.simstate_changed.emit()
        self._move_disassembly_view_to_ip()

    def sync_state(self):
        """
        Synchronize cached simstate accessible via property `simstate` with
        remote target. Runs whenever the target enters a stopped state.
        """
        if not self._state_dirty or self.target is None or self.project is None:
            return

        self.simstate = self.project.factory.blank_state(add_options={angr.options.FAST_MEMORY})

        for r in self.simstate.arch.register_list:
            if r.general_purpose:
                rval = self.target.read_register(r.name)
                if rval is None:
                    _l.error('Unavailable reg on target %s', r.name)
                    return
                setattr(self.simstate.regs, r.name, rval)

        self.realtime_simstate = self.simstate

        if self.trace_path is not None:
            self.load_trace()

        self.simstate_changed.emit()
        self._move_disassembly_view_to_ip()
        self._state_dirty = False

'''
