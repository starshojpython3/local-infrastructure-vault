from __future__ import annotations

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.database import Database
from app.vault_service import VaultService


class LoginWindow(QWidget):
    unlocked = pyqtSignal(object, object)

    def __init__(self, db: Database) -> None:
        super().__init__()
        self.setWindowTitle("Password Vault - Unlock")
        self.resize(460, 280)
        self.setWindowIcon(QApplication.instance().windowIcon())

        self.vault_service = VaultService(db)
        self._new_vault = False
        self._failed_attempts = 0
        self._lockout_level = 0
        self._lockout_remaining = 0

        self._lockout_timer = QTimer(self)
        self._lockout_timer.setInterval(1000)
        self._lockout_timer.timeout.connect(self._tick_lockout)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        self.info = QLabel()
        self.lockout_info = QLabel("")

        form = QFormLayout()
        form.setSpacing(10)

        self.master_input = QLineEdit()
        self.master_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.master_toggle = QPushButton("Show")
        self.master_toggle.setCheckable(True)
        self.master_toggle.toggled.connect(lambda checked: self._toggle_password(self.master_input, self.master_toggle, checked))

        self.new_master_input = QLineEdit()
        self.new_master_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_master_toggle = QPushButton("Show")
        self.new_master_toggle.setCheckable(True)
        self.new_master_toggle.toggled.connect(lambda checked: self._toggle_password(self.new_master_input, self.new_master_toggle, checked))

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_toggle = QPushButton("Show")
        self.confirm_toggle.setCheckable(True)
        self.confirm_toggle.toggled.connect(lambda checked: self._toggle_password(self.confirm_input, self.confirm_toggle, checked))

        form.addRow("Master password", self._with_toggle(self.master_input, self.master_toggle))
        form.addRow("New master password", self._with_toggle(self.new_master_input, self.new_master_toggle))
        form.addRow("Confirm master password", self._with_toggle(self.confirm_input, self.confirm_toggle))

        self.submit_btn = QPushButton("Continue")

        layout.addWidget(self.info)
        layout.addWidget(self.lockout_info)
        layout.addLayout(form)
        layout.addWidget(self.submit_btn)

        self.submit_btn.clicked.connect(self._on_submit)
        self.master_input.returnPressed.connect(self._on_submit)
        self.new_master_input.returnPressed.connect(self._on_submit)
        self.confirm_input.returnPressed.connect(self._on_submit)

        self._refresh_mode()

    @staticmethod
    def _with_toggle(field: QLineEdit, button: QPushButton) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(field)
        row.addWidget(button)
        return holder

    @staticmethod
    def _toggle_password(field: QLineEdit, button: QPushButton, checked: bool) -> None:
        field.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
        button.setText("Hide" if checked else "Show")

    def _clear_password_fields(self) -> None:
        for field in (self.master_input, self.new_master_input, self.confirm_input):
            field.clear()
            field.setEchoMode(QLineEdit.EchoMode.Password)
        for btn in (self.master_toggle, self.new_master_toggle, self.confirm_toggle):
            btn.setChecked(False)
            btn.setText("Show")

    def _refresh_mode(self) -> None:
        self._new_vault = not self.vault_service.get_vault_meta().is_initialized
        self._clear_password_fields()
        if self._new_vault:
            self.info.setText("Set master password for new vault")
            self.master_input.hide()
            self.master_toggle.hide()
            self.new_master_input.show()
            self.new_master_toggle.show()
            self.confirm_input.show()
            self.confirm_toggle.show()
        else:
            self.info.setText("Enter master password")
            self.master_input.show()
            self.master_toggle.show()
            self.new_master_input.hide()
            self.new_master_toggle.hide()
            self.confirm_input.hide()
            self.confirm_toggle.hide()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._refresh_mode()

    def _register_failed_attempt(self) -> None:
        self._failed_attempts += 1
        if self._failed_attempts < 5:
            return

        self._failed_attempts = 0
        self._lockout_level = min(self._lockout_level + 1, 3)
        delays = {1: 30, 2: 60, 3: 120}
        self._lockout_remaining = delays[self._lockout_level]
        self.submit_btn.setEnabled(False)
        self._update_lockout_label()
        self._lockout_timer.start()

    def _tick_lockout(self) -> None:
        if self._lockout_remaining <= 0:
            self._lockout_timer.stop()
            self.submit_btn.setEnabled(True)
            self.lockout_info.clear()
            return
        self._lockout_remaining -= 1
        self._update_lockout_label()

    def _update_lockout_label(self) -> None:
        if self._lockout_remaining > 0:
            self.lockout_info.setText(f"Too many failed attempts. Try again in {self._lockout_remaining}s.")
        else:
            self.lockout_info.clear()

    def _on_submit(self) -> None:
        if self._lockout_remaining > 0:
            QMessageBox.warning(self, "Locked", f"Login is temporarily locked for {self._lockout_remaining}s.")
            return

        if self._new_vault:
            new_password = self.new_master_input.text()
            confirm = self.confirm_input.text()
            if not new_password:
                QMessageBox.warning(self, "Validation", "Master password is required.")
                return
            if new_password != confirm:
                QMessageBox.warning(self, "Validation", "Passwords do not match.")
                return
            self.vault_service.initialize_vault(new_password)
            key = self.vault_service.unlock(new_password)
        else:
            password = self.master_input.text()
            if not password:
                QMessageBox.warning(self, "Validation", "Master password is required.")
                return
            key = self.vault_service.unlock(password)

        if not key:
            self._register_failed_attempt()
            QMessageBox.critical(self, "Access denied", "Invalid master password.")
            return

        self._failed_attempts = 0
        self._lockout_level = 0
        self._lockout_remaining = 0
        self._lockout_timer.stop()
        self.submit_btn.setEnabled(True)
        self.lockout_info.clear()
        self._clear_password_fields()
        self.unlocked.emit(self.vault_service, key)
        self.hide()
