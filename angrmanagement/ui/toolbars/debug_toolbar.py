import os
import qtawesome as qta
from PySide2.QtGui import QIcon
from PySide2.QtWidgets import QLabel
from angrmanagement.config import IMG_LOCATION

from ...config import Conf

from .toolbar import Toolbar, ToolbarAction, ToolbarSplitter

class DebugToolbar(Toolbar):
    """
    Debugger Contral Toolbar
    """
    def __init__(self, main_window: 'MainWindow'):
        super().__init__(main_window, 'DebugToolbar')
        self.workspace = main_window.workspace

        ico = lambda fname: QIcon(os.path.join(IMG_LOCATION, fname))

        self._start_act = ToolbarAction(qta.icon("fa5s.running", color=Conf.palette_buttontext),
            'Launch', 'Launch/Connect', self._on_start)
        self._stop_act = ToolbarAction(qta.icon("fa5s.stop-circle", color=Conf.palette_buttontext),
            'Stop', 'Stop', self._on_stop)
        self._cont_backward_act = ToolbarAction(qta.icon("fa5s.fast-backward", color=Conf.palette_buttontext),
            'Continue-Backward', 'Continue-Backward', self._on_cont_backward)
        self._step_backward_act = ToolbarAction(qta.icon("fa5s.step-backward", color=Conf.palette_buttontext),
            'Step-Backward', 'Step-Backward', self._on_step_backward)
        self._cont_act = ToolbarAction(qta.icon("fa5s.play-circle", color=Conf.palette_buttontext),
            'Continue', 'Continue', self._on_cont)
        self._halt_act = ToolbarAction(qta.icon("fa5s.pause-circle", color=Conf.palette_buttontext),
            'Halt', 'Halt', self._on_halt)
        self._step_act = ToolbarAction(qta.icon("fa5s.step-forward", color=Conf.palette_buttontext),
            'Step', 'Step', self._on_step)

        self.actions = [
            self._start_act, self._stop_act, ToolbarSplitter(),
            self._cont_backward_act, self._step_backward_act, self._cont_act, self._halt_act, self._step_act]
        self.qtoolbar()

        self._run_lbl = QLabel()
        self._run_lbl.setText('')
        self._cached.addWidget(self._run_lbl)

        self.workspace.instance.debugger.am_subscribe(self._on_debugger_updated)
        self._update_state()

    def _on_debugger_updated(self, *args, **kwargs):
        dbg = self.workspace.instance.debugger
        if not dbg.am_none:
            dbg.state_changed.connect(self._update_state)

    def _update_state(self):
        dbg = self.workspace.instance.debugger.am_obj
        dbg_active = dbg is not None
        q = lambda a: self._cached_actions[a]
        q(self._start_act).setEnabled(not dbg_active)
        q(self._stop_act).setEnabled(dbg_active and dbg.can_stop)
        q(self._step_act).setEnabled(dbg_active and dbg.can_step_forward)
        q(self._step_backward_act).setEnabled(dbg_active and dbg.can_step_backward)
        q(self._cont_act).setEnabled(dbg_active and dbg.can_continue_forward)
        q(self._cont_backward_act).setEnabled(dbg_active and dbg.can_continue_backward)
        q(self._halt_act).setEnabled(dbg_active and dbg.can_halt)
        if dbg_active:
            self._run_lbl.setText(dbg.state_description)
        else:
            self._run_lbl.setText('')

    def _on_start(self):
        self.workspace.start_debugger()

    def _on_stop(self):
        self.workspace.instance.debugger.stop()

    def _on_cont(self):
        self.workspace.instance.debugger.continue_forward()

    def _on_cont_backward(self):
        self.workspace.instance.debugger.continue_backward()

    def _on_halt(self):
        self.workspace.instance.debugger.halt()

    def _on_step(self):
        self.workspace.instance.debugger.step_forward()

    def _on_step_backward(self):
        self.workspace.instance.debugger.step_backward()
