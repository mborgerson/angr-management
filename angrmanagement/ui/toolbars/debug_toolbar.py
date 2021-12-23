import os
from typing import Optional

import qtawesome as qta
from PySide2.QtCore import QAbstractItemModel, Qt, QModelIndex
from PySide2.QtGui import QIcon
from PySide2.QtWidgets import QLabel, QComboBox, QAction, QMenu, QPushButton
from angrmanagement.config import IMG_LOCATION
from angrmanagement.logic.debugger import DebuggerWatcher

from ...config import Conf

from .toolbar import Toolbar, ToolbarAction, ToolbarSplitter


class AvailableDebuggersModel(QAbstractItemModel):
    def __init__(self, workspace: 'Workspace'):
        super().__init__()
        self.debugger_mgr: 'DebuggerManager' = workspace.instance.debugger_mgr
        self.debugger_list_mgr: 'DebuggerListManager' = workspace.instance.debugger_list_mgr
        self.last_str = {}

    def rowCount(self, parent):
        return len(self.debugger_list_mgr.debugger_list) + 1

    def columnCount(self, parent):
        return 1

    def index(self, row, col, parent):
        return self.createIndex(row, col, None)

    def parent(self, index):
        return QModelIndex()

    def data(self, index, role):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        row = index.row()
        dbg = self.index_to_debugger(row)
        self.last_str[row] = 'No Debugger' if dbg is None else str(dbg)
        return self.last_str[row]

    def debugger_to_index(self, dbg: Optional['Debugger']) -> int:
        return 0 if dbg is None else (self.debugger_list_mgr.debugger_list.index(dbg) + 1)

    def index_to_debugger(self, index: int) -> Optional['Debugger']:
        return None if index == 0 else (self.debugger_list_mgr.debugger_list[index - 1])


class DebugToolbar(Toolbar):
    """
    Debugger Control Toolbar
    """
    def __init__(self, main_window: 'MainWindow'):
        super().__init__(main_window, 'DebugToolbar')
        self.workspace: 'Workspace' = main_window.workspace
        self.instance: 'Instance' = self.workspace.instance

        self._cont_backward_act = ToolbarAction(qta.icon("fa5s.fast-backward", color=Conf.palette_buttontext),
            'Continue-Backward', 'Reverse-Continue', self._on_cont_backward)
        self._step_backward_act = ToolbarAction(qta.icon("fa5s.step-backward", color=Conf.palette_buttontext),
            'Step-Backward', 'Reverse-Step', self._on_step_backward)
        self._cont_act = ToolbarAction(qta.icon("fa5s.play", color=Conf.palette_buttontext),
            'Continue', 'Continue', self._on_cont)
        self._halt_act = ToolbarAction(qta.icon("fa5s.pause", color=Conf.palette_buttontext),
            'Halt', 'Halt', self._on_halt)
        self._step_act = ToolbarAction(qta.icon("fa5s.step-forward", color=Conf.palette_buttontext),
            'Step', 'Step', self._on_step)

        self._start_act = ToolbarAction(qta.icon("fa5s.running", color=Conf.palette_buttontext),
            'Launch', 'New Debugger', self._on_start)
        self._stop_act = ToolbarAction(qta.icon("fa5s.stop-circle", color=Conf.palette_buttontext),
            'Stop', 'Stop Debugging', self._on_stop)

        self.actions = [
            self._cont_backward_act, self._step_backward_act, self._cont_act, self._halt_act, self._step_act,
            ToolbarSplitter(),
            self._start_act, self._stop_act
        ]
        self.qtoolbar()

        self._cached.visibilityChanged.connect(self._on_visibility_changed)

        self._dbg_list_mgr = self.instance.debugger_list_mgr
        self._dbg_mgr = self.instance.debugger_mgr

        self._new_debugger_menu = QMenu(self._cached)
        self._new_debugger_menu.aboutToShow.connect(self._update_new_debugger_list)
        self._cached_actions[self._start_act].setMenu(self._new_debugger_menu)

        self._debugger_model = AvailableDebuggersModel(self.workspace)
        self._debugger_combo = QComboBox()
        self._debugger_combo.setMinimumWidth(250)
        self._debugger_combo.setModel(self._debugger_model)
        self._debugger_combo.activated.connect(self._select_debugger_by_index)
        self._cached.addWidget(self._debugger_combo)
        self._update_debugger_list_combo()

        self._run_lbl = QLabel()
        self._run_lbl.setText('')
        self._cached.addWidget(self._run_lbl)

        self._dbg_watcher: Optional[DebuggerWatcher] = None

    def _on_visibility_changed(self, visible: bool):
        if visible:
            self.instance.debugger_list_mgr.debugger_list.am_subscribe(self._update_debugger_list_combo)
            self._dbg_watcher = DebuggerWatcher(self._debugger_state_changed, self._dbg_mgr.debugger)
        else:
            self._dbg_watcher.shutdown()
            self._dbg_watcher = None

    def _select_debugger_by_index(self, index: int):
        dbg = self._debugger_model.index_to_debugger(index)
        self._dbg_mgr.set_debugger(dbg)

    def _debugger_state_changed(self):
        self._update_debugger_list_combo()
        self._update_state()

    def _select_current_debugger_in_combo(self, *args, **kwargs):
        dbg = self._dbg_mgr.debugger.am_obj
        self._debugger_combo.setCurrentIndex(self._debugger_model.debugger_to_index(dbg))

    def _update_new_debugger_list(self):
        self._new_debugger_menu.clear()

        act = QAction("New simulation...", self._new_debugger_menu)
        act.triggered.connect(self.workspace.main_window.open_newstate_dialog)
        self._new_debugger_menu.addAction(act)

        act = QAction("New trace debugger", self._new_debugger_menu)
        act.triggered.connect(self.workspace.main_window.start_trace_debugger)
        self._new_debugger_menu.addAction(act)

    def _update_debugger_list_combo(self, *args, **kwargs):
        # for _ in range(self._debugger_combo.count()):
        #     self._debugger_combo.removeItem(0)
        # self._debugger_combo.addItem('No Debugger', None)
        dl = self.instance.debugger_list_mgr.debugger_list
        # for d in dl:
        #     self._debugger_combo.addItem(str(d), d)
        self._debugger_combo.setEnabled(len(dl) > 0)
        self._select_current_debugger_in_combo()
        self._debugger_model.layoutChanged.emit()
        self._debugger_combo.update()

    def _update_state(self):
        dbg = self._dbg_mgr.debugger.am_obj
        dbg_active = dbg is not None
        q = lambda a: self._cached_actions[a]
        q(self._step_act).setEnabled(dbg_active and dbg.can_step_forward)
        q(self._step_backward_act).setEnabled(dbg_active and dbg.can_step_backward)
        q(self._cont_backward_act).setEnabled(dbg_active and dbg.can_continue_backward)
        q(self._cont_act).setEnabled(dbg_active and dbg.can_continue_forward)
        q(self._cont_act).setVisible(not (dbg_active and dbg.can_halt))
        q(self._halt_act).setEnabled(dbg_active and dbg.can_halt)
        q(self._halt_act).setVisible(dbg_active and dbg.can_halt)
        q(self._start_act).setEnabled(True)
        q(self._stop_act).setEnabled(dbg_active and dbg.can_stop)

        if dbg_active:
            self._run_lbl.setText(dbg.state_description)
        else:
            self._run_lbl.setText('')

    def _on_start(self):
        # self.workspace.main_window.start_trace_debugger()
        self._cached.widgetForAction(self._cached_actions[self._start_act]).showMenu()

    def _on_stop(self):
        self._dbg_mgr.debugger.stop()
        self._dbg_list_mgr.remove_debugger(self._dbg_mgr.debugger.am_obj)

    def _on_cont(self):
        self._dbg_mgr.debugger.continue_forward()

    def _on_cont_backward(self):
        self._dbg_mgr.debugger.continue_backward()

    def _on_halt(self):
        self._dbg_mgr.debugger.halt()

    def _on_step(self):
        self._dbg_mgr.debugger.step_forward()

    def _on_step_backward(self):
        self._dbg_mgr.debugger.step_backward()
