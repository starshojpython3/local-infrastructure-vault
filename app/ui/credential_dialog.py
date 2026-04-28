from __future__ import annotations

import json
import secrets
import string
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtCore import QRegularExpression
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


CRED_TYPES = ["web", "ssh", "db", "api", "device", "gitlab", "vpn", "other"]
ENVIRONMENTS = ["prod", "dev", "test", "staging", "local", "other"]
AMBIGUOUS_CHARS = set("Il1O0|`'\"")


class CredentialDialog(QDialog):
    def __init__(
        self,
        organizations: list[dict[str, Any]],
        groups: list[dict[str, Any]],
        devices: list[dict[str, Any]],
        initial: dict[str, Any] | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Credential")
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            width = min(860, max(640, geo.width() - 80))
            height = min(740, max(520, geo.height() - 80))
            self.resize(width, height)
            self.setMaximumSize(width, height)
        else:
            self.resize(860, 700)

        self.organizations = organizations
        self.groups = groups
        self.devices = devices
        self._result_data: dict[str, Any] | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(scroll.Shape.NoFrame)
        content = QWidget()
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)

        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(10)

        self.org_combo = QComboBox()
        for org in organizations:
            self.org_combo.addItem(org["name"], org["id"])

        self.group_combo = QComboBox()
        self.device_combo = QComboBox()

        self.type_combo = QComboBox()
        self.type_combo.addItems(CRED_TYPES)
        self.env_combo = QComboBox()
        self.env_combo.addItems(ENVIRONMENTS)

        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_password_btn = self._make_toggle_button(self.password_input)

        self.host_input = QLineEdit()
        self.ip_input = QLineEdit()
        self.port_input = QLineEdit()
        self.url_input = QLineEdit()
        self.ssh_user_input = QLineEdit()
        self.ssh_key_path_input = QLineEdit()

        self.ssh_private_key_input = QLineEdit()
        self.ssh_private_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_ssh_key_btn = self._make_toggle_button(self.ssh_private_key_input)

        self.ssh_passphrase_input = QLineEdit()
        self.ssh_passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_ssh_passphrase_btn = self._make_toggle_button(self.ssh_passphrase_input)

        self.notes_input = QTextEdit()
        self.tags_input = QLineEdit()
        self.extra_input = QTextEdit()
        self.extra_input.setPlaceholderText('{"key": "value"}')

        self.exclude_ambiguous_checkbox = QCheckBox("Exclude ambiguous chars")
        self.generate_password_btn = QPushButton("Generate password")
        self.generate_password_btn.clicked.connect(self._generate_password)

        self.port_input.setInputMethodHints(Qt.InputMethodHint.ImhDigitsOnly)
        self.port_input.setValidator(QRegularExpressionValidator(QRegularExpression(r"^[0-9]{0,5}$")))

        form.addRow("Organization", self.org_combo)
        form.addRow("Group (optional)", self.group_combo)
        form.addRow("Device (optional)", self.device_combo)
        form.addRow("Type", self.type_combo)
        form.addRow("Environment", self.env_combo)
        form.addRow("Username", self.username_input)
        form.addRow("Password", self._secret_row(self.password_input, self.show_password_btn))

        generator_row = QWidget()
        generator_layout = QHBoxLayout(generator_row)
        generator_layout.setContentsMargins(0, 0, 0, 0)
        generator_layout.setSpacing(8)
        generator_layout.addWidget(self.generate_password_btn)
        generator_layout.addWidget(self.exclude_ambiguous_checkbox)
        generator_layout.addStretch(1)
        form.addRow("Password Tools", generator_row)

        form.addRow("Host", self.host_input)
        form.addRow("IP", self.ip_input)
        form.addRow("Port", self.port_input)
        form.addRow("URL", self.url_input)
        form.addRow("SSH User", self.ssh_user_input)
        form.addRow("SSH Key Path", self.ssh_key_path_input)
        form.addRow("SSH Private Key", self._secret_row(self.ssh_private_key_input, self.show_ssh_key_btn))
        form.addRow("SSH Passphrase", self._secret_row(self.ssh_passphrase_input, self.show_ssh_passphrase_btn))
        form.addRow(QLabel("Notes"), self.notes_input)
        form.addRow("Tags", self.tags_input)
        form.addRow(QLabel("Extra JSON"), self.extra_input)

        content_layout.addLayout(form)

        buttons = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        save_btn.setDefault(True)
        save_btn.setAutoDefault(True)
        buttons.addWidget(save_btn)
        buttons.addWidget(cancel_btn)
        content_layout.addLayout(buttons)

        save_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)

        for line_edit in [
            self.username_input,
            self.password_input,
            self.host_input,
            self.ip_input,
            self.port_input,
            self.url_input,
            self.ssh_user_input,
            self.ssh_key_path_input,
            self.ssh_private_key_input,
            self.ssh_passphrase_input,
            self.tags_input,
        ]:
            line_edit.returnPressed.connect(self.accept)

        self.org_combo.currentIndexChanged.connect(self._reload_group_device)
        self.group_combo.currentIndexChanged.connect(self._reload_device)

        self._reload_group_device()
        self._default_title = "Credential"

        if initial:
            self._fill_initial(initial)

    @staticmethod
    def _secret_row(field: QLineEdit, toggle_button: QPushButton) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(field)
        row.addWidget(toggle_button)
        return holder

    @staticmethod
    def _make_toggle_button(field: QLineEdit) -> QPushButton:
        button = QPushButton("Show")
        button.setCheckable(True)

        def toggle(checked: bool) -> None:
            field.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
            button.setText("Hide" if checked else "Show")

        button.toggled.connect(toggle)
        return button

    def _reset_secret_visibility(self) -> None:
        for button in (self.show_password_btn, self.show_ssh_key_btn, self.show_ssh_passphrase_btn):
            button.setChecked(False)
            button.setText("Show")
        for field in (self.password_input, self.ssh_private_key_input, self.ssh_passphrase_input):
            field.setEchoMode(QLineEdit.EchoMode.Password)

    def _generate_password(self) -> None:
        alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+[]{};:,.?/"
        if self.exclude_ambiguous_checkbox.isChecked():
            alphabet = "".join(ch for ch in alphabet if ch not in AMBIGUOUS_CHARS)
        password = "".join(secrets.choice(alphabet) for _ in range(20))
        self.password_input.setText(password)
        self.show_password_btn.setChecked(False)

    def _reload_group_device(self) -> None:
        org_id = self.org_combo.currentData()
        self.group_combo.blockSignals(True)
        self.group_combo.clear()
        self.group_combo.addItem("-- None --", None)
        for g in self.groups:
            if g["organization_id"] == org_id:
                label = g["name"]
                if g.get("parent_group_id"):
                    label = f"{label} (subgroup)"
                self.group_combo.addItem(label, g["id"])
        self.group_combo.blockSignals(False)
        self._reload_device()

    def _reload_device(self) -> None:
        group_id = self.group_combo.currentData()
        self.device_combo.clear()
        self.device_combo.addItem("-- None --", None)
        for d in self.devices:
            if group_id is not None and d["group_id"] == group_id:
                self.device_combo.addItem(d["name"], d["id"])

    def _fill_initial(self, initial: dict[str, Any]) -> None:
        self._set_combo_data(self.org_combo, initial.get("organization_id"))
        self._reload_group_device()
        self._set_combo_data(self.group_combo, initial.get("group_id"))
        self._reload_device()
        self._set_combo_data(self.device_combo, initial.get("device_id"))

        self._default_title = (initial.get("title") or "").strip() or "Credential"
        self._set_combo_text(self.type_combo, initial.get("type", "other"))
        self._set_combo_text(self.env_combo, initial.get("environment", "other"))

        payload = initial.get("payload", {})
        self.username_input.setText(payload.get("username", ""))
        self.password_input.setText(payload.get("password", ""))
        self.host_input.setText(payload.get("host", ""))
        self.ip_input.setText(payload.get("ip", ""))
        self.port_input.setText(str(payload.get("port", "")))
        self.url_input.setText(payload.get("url", ""))
        self.ssh_user_input.setText(payload.get("ssh_user", ""))
        self.ssh_key_path_input.setText(payload.get("ssh_key_path", ""))
        self.ssh_private_key_input.setText(payload.get("ssh_private_key", ""))
        self.ssh_passphrase_input.setText(payload.get("ssh_passphrase", ""))
        self.notes_input.setPlainText(payload.get("notes", ""))
        self.tags_input.setText(initial.get("tags", ""))
        self.extra_input.setPlainText(json.dumps(payload.get("extra", {}), ensure_ascii=False, indent=2))
        self._reset_secret_visibility()

    @staticmethod
    def _set_combo_data(combo: QComboBox, data: Any) -> None:
        for i in range(combo.count()):
            if combo.itemData(i) == data:
                combo.setCurrentIndex(i)
                return

    @staticmethod
    def _set_combo_text(combo: QComboBox, value: str) -> None:
        idx = combo.findText(value)
        if idx >= 0:
            combo.setCurrentIndex(idx)

    def get_data(self) -> dict[str, Any] | None:
        if self._result_data is not None:
            return self._result_data

        username = self.username_input.text().strip()
        host = self.host_input.text().strip()
        url = self.url_input.text().strip()
        title = username or host or url or self._default_title

        extra_text = self.extra_input.toPlainText().strip()
        extra: dict[str, Any] = {}
        if extra_text:
            try:
                parsed = json.loads(extra_text)
            except json.JSONDecodeError:
                QMessageBox.warning(self, "Validation", "Extra must be valid JSON.")
                return None
            if not isinstance(parsed, dict):
                QMessageBox.warning(self, "Validation", "Extra JSON must be an object.")
                return None
            extra = parsed

        return {
            "organization_id": self.org_combo.currentData(),
            "group_id": self.group_combo.currentData(),
            "device_id": self.device_combo.currentData(),
            "title": title,
            "type": self.type_combo.currentText(),
            "environment": self.env_combo.currentText(),
            "tags": self.tags_input.text().strip(),
            "payload": {
                "username": self.username_input.text().strip(),
                "password": self.password_input.text(),
                "host": self.host_input.text().strip(),
                "ip": self.ip_input.text().strip(),
                "port": self.port_input.text().strip(),
                "url": self.url_input.text().strip(),
                "ssh_user": self.ssh_user_input.text().strip(),
                "ssh_key_path": self.ssh_key_path_input.text().strip(),
                "ssh_private_key": self.ssh_private_key_input.text(),
                "ssh_passphrase": self.ssh_passphrase_input.text(),
                "notes": self.notes_input.toPlainText(),
                "extra": extra,
            },
        }

    def accept(self) -> None:
        data = self.get_data()
        if not data:
            return
        self._result_data = data
        super().accept()

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            fw = self.focusWidget()
            if isinstance(fw, QTextEdit) and fw in (self.notes_input, self.extra_input):
                super().keyPressEvent(event)
                return
            self.accept()
            event.accept()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event) -> None:
        self._reset_secret_visibility()
        super().closeEvent(event)
