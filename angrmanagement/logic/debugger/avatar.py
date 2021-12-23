import subprocess
import logging
import os
import re
from tempfile import NamedTemporaryFile
from typing import Optional, Sequence

import angr
from PySide2.QtCore import Signal
from angr import SimState
from angr_targets import ConcreteTarget, AvatarGDBConcreteTarget
import avatar2
from avatar2 import Avatar, GDBTarget, TargetStates
from cle.gdb import convert_info_proc_maps

from .debugger import Debugger
from ..threads import gui_thread_schedule_async


_l = logging.getLogger(name=__name__)


class DebuggerAvatarGDBConcreteTarget(AvatarGDBConcreteTarget):
    """
    Custom concrete target.
    """

    def __init__(self, avatar, target):
        # FIXME: Hack around AvatarGDBConcreteTarget's constructor
        ConcreteTarget.__init__(self)
        self.avatar = avatar
        self.target = target
        self.page_size = 0x1000


class AvatarGdbDebugger(Debugger):
    """
    Interface to Avatar2's GDB target.
    """

    connect_failed: Signal = Signal()

    def __init__(self, workspace,
                 remote_host: str = '127.0.0.1', remote_port: int = 3333,
                 local_binary_command: Optional[Sequence[str]] = None
                 ):
        super().__init__(workspace)
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
        self._simstate: SimState = None

        self.avatar: Avatar = None
        self.angr_target: 'ConcreteTarget' = None
        self.project: angr.Project = None
        self.target: GDBTarget = None
        self.breakpoints = {}

    @property
    def simstate(self):
        return self._simstate

    def __str__(self):
        return f'{self._remote_host}:{self._remote_port} '

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
        self._simstate = None
        self.state_changed.emit()

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

        self._simstate = self.project.factory.blank_state(add_options={angr.options.FAST_MEMORY})

        for r in self.simstate.arch.register_list:
            if r.general_purpose:
                rval = self.target.read_register(r.name)
                if rval is None:
                    _l.error('Unavailable reg on target %s', r.name)
                    return
                setattr(self.simstate.regs, r.name, rval)

        self.simstate_changed.emit()
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
        self._state_dirty = False

'''
