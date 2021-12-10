from typing import Optional

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QDialogButtonBox


class StartDebugger(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Start debugging')
        self._remote_host_edit: Optional[QLineEdit] = None
        self._init_widgets()
        self.setLayout(self.main_layout)

        self.host: str = ''
        self.port: int = 0

    #
    # Private methods
    #

    def _init_widgets(self):
        self.main_layout = QVBoxLayout()

        hlayout = QHBoxLayout()
        hlayout.addWidget(QLabel('Remote Host:', self))
        self._remote_host_edit = QLineEdit('127.0.0.1:3333', self)
        hlayout.addWidget(self._remote_host_edit)
        self.main_layout.addLayout(hlayout)

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel
                                   | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.reject)
        buttons_lyt = QHBoxLayout()
        buttons_lyt.addWidget(buttons)
        self.main_layout.addLayout(buttons_lyt)

    def _on_ok_clicked(self):
        host, port = self._remote_host_edit.text().split(':')
        port = int(port)

        self.host = host
        self.port = port

        self.done(QDialog.DialogCode.Accepted)
