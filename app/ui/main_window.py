from __future__ import annotations

import gc
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

import config
from PyQt6.QtCore import QEvent, QTimer, Qt
from PyQt6.QtGui import QIcon, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QHeaderView,
    QHBoxLayout,
    QFileDialog,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTextEdit,
    QFrame,
    QDialog,
    QDialogButtonBox,
    QSplitter,
    QSizePolicy,
    QStyle,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.search_service import SearchService
from app.security import is_secret_field_name, mask_secret
from app.vault_service import VaultService
from .credential_dialog import CredentialDialog


class ChangeMasterPasswordDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Change Master Password")
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.old_password = QLineEdit()
        self.new_password = QLineEdit()
        self.confirm_password = QLineEdit()
        for field in (self.old_password, self.new_password, self.confirm_password):
            field.setEchoMode(QLineEdit.EchoMode.Password)

        self.old_toggle = self._toggle_btn(self.old_password)
        self.new_toggle = self._toggle_btn(self.new_password)
        self.confirm_toggle = self._toggle_btn(self.confirm_password)

        form.addRow("Current password", self._row(self.old_password, self.old_toggle))
        form.addRow("New password", self._row(self.new_password, self.new_toggle))
        form.addRow("Confirm new password", self._row(self.confirm_password, self.confirm_toggle))
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _row(field: QLineEdit, button: QPushButton) -> QWidget:
        wrapper = QWidget()
        row = QHBoxLayout(wrapper)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(field)
        row.addWidget(button)
        return wrapper

    @staticmethod
    def _toggle_btn(field: QLineEdit) -> QPushButton:
        button = QPushButton("Show")
        button.setCheckable(True)

        def toggle(checked: bool) -> None:
            field.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
            button.setText("Hide" if checked else "Show")

        button.toggled.connect(toggle)
        return button


class MainWindow(QMainWindow):
    def __init__(self, vault_service: VaultService, encryption_key: bytes, on_lock=None) -> None:
        super().__init__()
        self.setWindowIcon(QApplication.instance().windowIcon())
        self.vault_service = vault_service
        self.encryption_key = encryption_key
        self._on_lock = on_lock
        self.search_service = SearchService()
        self.show_passwords = False
        self.all_credentials = []
        self.filtered_credentials = []
        self._updating_device_form = False
        self._current_device_cred_id: int | None = None
        self._device_edit_mode = False
        self._details_open = False
        self._quit_requested = False
        self._auto_lock_in_progress = False
        self._clipboard_secret_fingerprint: str | None = None
        self._clipboard_secret_value: str | None = None
        self._clipboard_clear_timer: QTimer | None = None
        self._details_secrets_visible = False
        self._details_rows: list[tuple[str, str]] = []
        self.current_lang = "uk"

        self.setWindowTitle(config.APP_NAME)
        self.resize(1200, 700)

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(14, 14, 14, 14)
        root_layout.setSpacing(10)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.search_input = QLineEdit()
        controls.addWidget(self.search_input)
        self.lang_btn = QPushButton("UA")
        self.lang_btn.clicked.connect(self.toggle_language)
        controls.addWidget(self.lang_btn)
        self.info_btn = QPushButton("Info")
        self.info_btn.clicked.connect(self.show_app_info)
        controls.addWidget(self.info_btn)
        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(self.open_settings)
        self.settings_btn = settings_btn
        controls.addWidget(settings_btn)
        root_layout.addLayout(controls)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([""])
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.open_tree_context_menu)
        self.tree.itemDoubleClicked.connect(self.on_tree_item_double_clicked)
        left_layout.addWidget(self.tree)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        self.device_context_label = QLabel("Credentials")
        right_layout.addWidget(self.device_context_label)

        self.device_editor_widget = QWidget()
        device_form = QFormLayout(self.device_editor_widget)
        device_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.DontWrapRows)
        device_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        device_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        device_form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.device_name_input = QLineEdit()
        self.device_name_input.setMinimumWidth(320)
        self.device_group_combo = QComboBox()
        self.device_group_combo.setMinimumWidth(320)
        device_buttons = QHBoxLayout()
        self.device_save_btn = QPushButton("Save Device")
        self.device_save_btn.clicked.connect(self.save_selected_device)
        device_buttons.addWidget(self.device_save_btn)
        device_form.addRow("Device Name", self.device_name_input)
        device_form.addRow("Group", self.device_group_combo)
        device_form.addRow(device_buttons)
        self.device_editor_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        self.device_editor_widget.setMaximumHeight(110)
        right_layout.addWidget(self.device_editor_widget)
        self.device_editor_widget.hide()

        self.cred_editor_widget = QWidget()
        cred_form = QFormLayout(self.cred_editor_widget)
        cred_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.DontWrapRows)
        cred_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        cred_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        cred_form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.ce_type = QComboBox()
        self.ce_type.addItems(["web", "ssh", "db", "api", "device", "gitlab", "vpn", "other"])
        self.ce_env = QComboBox()
        self.ce_env.addItems(["prod", "dev", "test", "staging", "local", "other"])
        self.ce_username = QLineEdit()
        self.ce_password = QLineEdit()
        self.ce_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.ce_password_toggle = self._make_line_secret_toggle(self.ce_password)
        self.ce_host = QLineEdit()
        self.ce_ip = QLineEdit()
        self.ce_port = QLineEdit()
        self.ce_url = QLineEdit()
        self.ce_ssh_user = QLineEdit()
        self.ce_ssh_key_path = QLineEdit()
        self.ce_ssh_private_key = QTextEdit()
        self.ce_ssh_private_key_toggle = QPushButton("Show")
        self.ce_ssh_private_key_toggle.setCheckable(True)
        self.ce_ssh_private_key_toggle.toggled.connect(self._toggle_private_key_visibility)
        self.ce_ssh_passphrase = QLineEdit()
        self.ce_ssh_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.ce_ssh_passphrase_toggle = self._make_line_secret_toggle(self.ce_ssh_passphrase)
        self.ce_notes = QTextEdit()
        self.ce_tags = QLineEdit()
        self.ce_extra = QTextEdit()
        for w in [
            self.ce_type,
            self.ce_env,
            self.ce_username,
            self.ce_password,
            self.ce_host,
            self.ce_ip,
            self.ce_port,
            self.ce_url,
            self.ce_ssh_user,
            self.ce_ssh_key_path,
            self.ce_ssh_passphrase,
            self.ce_tags,
        ]:
            w.setMinimumWidth(320)
        self.ce_ssh_private_key.setFixedHeight(70)
        self.ce_notes.setFixedHeight(70)
        self.ce_extra.setFixedHeight(80)
        cred_form.addRow("Type", self.ce_type)
        cred_form.addRow("Environment", self.ce_env)
        cred_form.addRow("Username", self.ce_username)
        cred_form.addRow("Password", self._secret_line_row(self.ce_password, self.ce_password_toggle))
        cred_form.addRow("Host", self.ce_host)
        cred_form.addRow("IP", self.ce_ip)
        cred_form.addRow("Port", self.ce_port)
        cred_form.addRow("URL", self.ce_url)
        cred_form.addRow("SSH User", self.ce_ssh_user)
        cred_form.addRow("SSH Key Path", self.ce_ssh_key_path)
        cred_form.addRow("SSH Private Key", self._secret_text_row(self.ce_ssh_private_key, self.ce_ssh_private_key_toggle))
        cred_form.addRow("SSH Passphrase", self._secret_line_row(self.ce_ssh_passphrase, self.ce_ssh_passphrase_toggle))
        cred_form.addRow("Notes", self.ce_notes)
        cred_form.addRow("Tags", self.ce_tags)
        cred_form.addRow("Extra JSON", self.ce_extra)
        for field in [
            self.ce_type,
            self.ce_env,
            self.ce_username,
            self.ce_password,
            self.ce_host,
            self.ce_ip,
            self.ce_port,
            self.ce_url,
            self.ce_ssh_user,
            self.ce_ssh_key_path,
            self.ce_ssh_private_key,
            self.ce_ssh_passphrase,
            self.ce_notes,
            self.ce_tags,
            self.ce_extra,
        ]:
            lbl = cred_form.labelForField(field)
            if lbl:
                lbl.setFixedWidth(130)

        cred_btn_row = QHBoxLayout()
        self.ce_save_btn = QPushButton("Save Credential")
        self.ce_copy_login_btn = QPushButton("Copy Login")
        self.ce_copy_password_btn = QPushButton("Copy Password")
        self.ce_copy_all_btn = QPushButton("Copy All")
        self.ce_save_btn.clicked.connect(self.save_selected_device_credential)
        self.ce_copy_login_btn.clicked.connect(self.copy_editor_login)
        self.ce_copy_password_btn.clicked.connect(self.copy_editor_password)
        self.ce_copy_all_btn.clicked.connect(self.copy_editor_all)
        cred_btn_row.addWidget(self.ce_save_btn)
        cred_btn_row.addWidget(self.ce_copy_login_btn)
        cred_btn_row.addWidget(self.ce_copy_password_btn)
        cred_btn_row.addWidget(self.ce_copy_all_btn)
        cred_form.addRow(cred_btn_row)
        self.cred_editor_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        self.cred_editor_widget.setMaximumHeight(360)
        right_layout.addWidget(self.cred_editor_widget)
        self.cred_editor_widget.hide()

        self.details_panel = QFrame()
        self.details_panel.setObjectName("DetailsPanel")
        details_layout = QVBoxLayout(self.details_panel)
        details_layout.setContentsMargins(10, 10, 10, 10)
        details_layout.setSpacing(8)
        self.details_title = QLabel("Details")
        self.details_title.setObjectName("DetailsTitle")
        details_layout.addWidget(self.details_title)
        self.details_secret_toggle_btn = QPushButton("Show secrets")
        self.details_secret_toggle_btn.clicked.connect(self._toggle_details_secrets_visibility)
        details_layout.addWidget(self.details_secret_toggle_btn)

        self.details_table = QTableWidget(0, 2)
        self.details_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.details_table.setEditTriggers(self.details_table.EditTrigger.NoEditTriggers)
        self.details_table.setSelectionBehavior(self.details_table.SelectionBehavior.SelectRows)
        self.details_table.setSelectionMode(self.details_table.SelectionMode.SingleSelection)
        details_hh = self.details_table.horizontalHeader()
        details_hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        details_hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        details_hh.setStretchLastSection(True)
        details_vh = self.details_table.verticalHeader()
        details_vh.setVisible(False)
        self.details_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.details_table.customContextMenuRequested.connect(self.open_details_context_menu)
        self.details_table.itemDoubleClicked.connect(lambda _item: self.copy_selected_detail_row())
        self.details_copy_shortcut = QShortcut(QKeySequence.StandardKey.Copy, self.details_table)
        self.details_copy_shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
        self.details_copy_shortcut.activated.connect(self.copy_selected_detail_row)
        details_layout.addWidget(self.details_table)
        right_layout.addWidget(self.details_panel)
        self.details_panel.hide()

        self.list_panel = QFrame()
        self.list_panel.setObjectName("ListPanel")
        list_layout = QVBoxLayout(self.list_panel)
        list_layout.setContentsMargins(10, 10, 10, 10)
        list_layout.setSpacing(8)

        self.table_title = QLabel("Credentials")
        self.table_title.setObjectName("DetailsTitle")
        list_layout.addWidget(self.table_title)

        self.table = QTableWidget(0, 9)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["", "", "", "", "", "", ""])
        self.table.setSelectionBehavior(self.table.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(self.table.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.open_table_context_menu)
        list_layout.addWidget(self.table)
        right_layout.addWidget(self.list_panel, 1)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([360, 840])
        root_layout.addWidget(splitter)

        self.status = QLabel("")
        self.status.hide()
        root_layout.addWidget(self.status)
        self.setCentralWidget(root)

        self.search_input.textChanged.connect(self.apply_search)
        self.tree.itemSelectionChanged.connect(self.apply_search)
        self.table.itemSelectionChanged.connect(self.on_table_selection_changed)
        self.table.cellClicked.connect(self.on_table_cell_clicked)

        self._apply_language()
        self.refresh_all()
        self._setup_tray()
        self._setup_auto_lock()

    def _tr(self, key: str) -> str:
        texts = {
            "uk": {
                "window_title": "Password Vault",
                "search_placeholder": "Глобальний пошук по несекретних полях (індекс у пам'яті)",
                "settings": "Налаштування",
                "info": "Інфо",
                "hierarchy": "Ієрархія",
                "credentials": "Облікові дані",
                "org_prefix": "Орг",
                "group_prefix": "Група",
                "device_prefix": "Пристрій",
                "selected_device": "Обраний пристрій: {name}",
                "device_name": "Назва пристрою",
                "group": "Група",
                "save_device": "Зберегти пристрій",
                "type": "Тип",
                "environment": "Середовище",
                "username": "Логін",
                "password": "Пароль",
                "host": "Хост",
                "ip": "IP",
                "port": "Порт",
                "url": "URL",
                "ssh_user": "SSH користувач",
                "ssh_key_path": "Шлях до SSH ключа",
                "ssh_private_key": "SSH приватний ключ",
                "ssh_passphrase": "SSH passphrase",
                "notes": "Нотатки",
                "tags": "Теги",
                "extra_json": "Extra JSON",
                "save_credential": "Зберегти credential",
                "copy_login": "Копіювати логін",
                "copy_password": "Копіювати пароль",
                "copy_all": "Копіювати все",
                "table_headers": ["Організація", "Група", "Пристрій", "Тип", "Сер.", "Логін", "Пароль"],
                "tray_open": "Відкрити",
                "tray_exit": "Вийти",
                "tray_msg": "Програма працює у фоні. Відкрийте її з іконки в треї.",
                "status_view": "Панель пристрою: режим ПЕРЕГЛЯДУ",
                "status_edit": "Панель пристрою: режим РЕДАГУВАННЯ",
                "status_credentials": "Облікових даних: {count}",
                "status_details_opened": "Деталі відкрито",
                "status_no_device_credentials": "На пристрої ще немає credentials",
                "status_copied": "Скопійовано (буфер очиститься через 45с)",
                "status_clipboard_cleared": "Буфер очищено",
                "menu_details": "Деталі",
                "menu_add": "Додати",
                "menu_add_org": "Додати організацію",
                "menu_edit": "Редагувати",
                "menu_delete": "Видалити",
                "dialog_settings": "Налаштування",
                "dialog_select_action": "Оберіть дію:",
                "action_change_master": "Змінити master пароль",
                "action_export_backup": "Експортувати backup БД",
                "about_title": "Про програму",
                "about_text": "Password Vault\nВерсія: {version}\n\nРозробник: Anton Pobyvanets\nEmail: antonpython3@gmail.com",
                "copy_row": "Копіювати рядок",
                "details_field": "Поле",
                "details_value": "Значення",
                "status_details_copied": "Деталі скопійовано",
                "show": "Показати",
                "hide": "Приховати",
                "show_secrets": "Показати секрети",
                "hide_secrets": "Сховати секрети",
            },
            "en": {
                "window_title": "Password Vault",
                "search_placeholder": "Global search across non-secret fields (RAM index)",
                "settings": "Settings",
                "info": "Info",
                "hierarchy": "Hierarchy",
                "credentials": "Credentials",
                "org_prefix": "Org",
                "group_prefix": "Group",
                "device_prefix": "Device",
                "selected_device": "Selected device: {name}",
                "device_name": "Device Name",
                "group": "Group",
                "save_device": "Save Device",
                "type": "Type",
                "environment": "Environment",
                "username": "Username",
                "password": "Password",
                "host": "Host",
                "ip": "IP",
                "port": "Port",
                "url": "URL",
                "ssh_user": "SSH User",
                "ssh_key_path": "SSH Key Path",
                "ssh_private_key": "SSH Private Key",
                "ssh_passphrase": "SSH Passphrase",
                "notes": "Notes",
                "tags": "Tags",
                "extra_json": "Extra JSON",
                "save_credential": "Save Credential",
                "copy_login": "Copy Login",
                "copy_password": "Copy Password",
                "copy_all": "Copy All",
                "table_headers": ["Organization", "Group", "Device", "Type", "Env", "Username", "Password"],
                "tray_open": "Open",
                "tray_exit": "Exit",
                "tray_msg": "App is running in background. Open from system tray.",
                "status_view": "Device panel: VIEW mode",
                "status_edit": "Device panel: EDIT mode",
                "status_credentials": "Credentials: {count}",
                "status_details_opened": "Details opened",
                "status_no_device_credentials": "Device has no credentials yet",
                "status_copied": "Copied (clipboard auto-clears in 45s)",
                "status_clipboard_cleared": "Clipboard cleared",
                "menu_details": "Details",
                "menu_add": "Add",
                "menu_add_org": "Add Organization",
                "menu_edit": "Edit",
                "menu_delete": "Delete",
                "dialog_settings": "Settings",
                "dialog_select_action": "Select action:",
                "action_change_master": "Change Master Password",
                "action_export_backup": "Export database backup",
                "about_title": "About",
                "about_text": "Password Vault\nVersion: {version}\n\nDeveloper: Anton Pobyvanets\nEmail: antonpython3@gmail.com",
                "copy_row": "Copy Row",
                "details_field": "Field",
                "details_value": "Value",
                "status_details_copied": "Details copied",
                "show": "Show",
                "hide": "Hide",
                "show_secrets": "Show secrets",
                "hide_secrets": "Hide secrets",
            },
        }
        return texts[self.current_lang][key]
    def _apply_language(self) -> None:
        self.setWindowTitle(self._tr("window_title"))
        self.search_input.setPlaceholderText(self._tr("search_placeholder"))
        self.settings_btn.setText(self._tr("settings"))
        self.info_btn.setText(self._tr("info"))
        self.lang_btn.setText("EN" if self.current_lang == "uk" else "UA")
        self.tree.setHeaderLabels([self._tr("hierarchy")])
        self.table.setHorizontalHeaderLabels(self._tr("table_headers"))
        self.device_save_btn.setText(self._tr("save_device"))
        self.ce_save_btn.setText(self._tr("save_credential"))
        self.ce_copy_login_btn.setText(self._tr("copy_login"))
        self.ce_copy_password_btn.setText(self._tr("copy_password"))
        self.ce_copy_all_btn.setText(self._tr("copy_all"))
        self.details_title.setText(self._tr("menu_details"))
        self._apply_secret_toggle_labels()
        self.table_title.setText("Credentials" if self.current_lang == "en" else "Облікові дані")
        self.details_table.setHorizontalHeaderLabels([self._tr("details_field"), self._tr("details_value")])
        if not self._selected_scope() or self._selected_scope().get("kind") != "device":
            self.device_context_label.clear()
            self.device_context_label.hide()
        self._setup_forms_labels()

    def _setup_forms_labels(self) -> None:
        df = self.device_editor_widget.layout()
        if isinstance(df, QFormLayout):
            df.setWidget(0, QFormLayout.ItemRole.LabelRole, QLabel(self._tr("device_name")))
            df.setWidget(1, QFormLayout.ItemRole.LabelRole, QLabel(self._tr("group")))
        cf = self.cred_editor_widget.layout()
        if isinstance(cf, QFormLayout):
            labels = [
                self._tr("type"),
                self._tr("environment"),
                self._tr("username"),
                self._tr("password"),
                self._tr("host"),
                self._tr("ip"),
                self._tr("port"),
                self._tr("url"),
                self._tr("ssh_user"),
                self._tr("ssh_key_path"),
                self._tr("ssh_private_key"),
                self._tr("ssh_passphrase"),
                self._tr("notes"),
                self._tr("tags"),
                self._tr("extra_json"),
            ]
            for idx, text in enumerate(labels):
                cf.setWidget(idx, QFormLayout.ItemRole.LabelRole, QLabel(text))

    def toggle_language(self) -> None:
        self.current_lang = "en" if self.current_lang == "uk" else "uk"
        self._apply_language()
        self._apply_tray_language()
        self._build_tree()
        self.apply_search()

    def _setup_tray(self) -> None:
        app_icon = QApplication.instance().windowIcon() if QApplication.instance() else QIcon()
        if app_icon and not app_icon.isNull():
            icon = app_icon
        else:
            icon_path_ico = Path(config.BASE_DIR) / "app" / "assets" / "app_icon.ico"
            icon_path_svg = Path(config.BASE_DIR) / "app" / "assets" / "app_icon.svg"
            if icon_path_ico.exists():
                icon = QIcon(str(icon_path_ico))
            elif icon_path_svg.exists():
                icon = QIcon(str(icon_path_svg))
            else:
                icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self.setWindowIcon(icon)
        self.tray_icon = QSystemTrayIcon(icon, self)
        self.tray_icon.setToolTip(config.APP_NAME)

        self.tray_menu = QMenu(self)
        self.tray_open_action = self.tray_menu.addAction("")
        self.tray_exit_action = self.tray_menu.addAction("")
        self.tray_open_action.triggered.connect(self._restore_from_tray)
        self.tray_exit_action.triggered.connect(self._exit_from_tray)
        self.tray_icon.setContextMenu(self.tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()
        self._apply_tray_language()

    def _apply_secret_toggle_labels(self) -> None:
        self.ce_password_toggle.setText(self._tr("hide") if self.ce_password_toggle.isChecked() else self._tr("show"))
        self.ce_ssh_passphrase_toggle.setText(
            self._tr("hide") if self.ce_ssh_passphrase_toggle.isChecked() else self._tr("show")
        )
        self.ce_ssh_private_key_toggle.setText(
            self._tr("hide") if self.ce_ssh_private_key_toggle.isChecked() else self._tr("show")
        )
        self.details_secret_toggle_btn.setText(
            self._tr("hide_secrets") if self._details_secrets_visible else self._tr("show_secrets")
        )

    def _setup_auto_lock(self) -> None:
        self._auto_lock_timer = QTimer(self)
        self._auto_lock_timer.setSingleShot(True)
        self._auto_lock_timer.timeout.connect(self._auto_lock)
        app = QApplication.instance()
        if app:
            app.installEventFilter(self)
        self._reset_auto_lock_timer()

    @staticmethod
    def _secret_line_row(field: QLineEdit, button: QPushButton) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(field)
        row.addWidget(button)
        return holder

    @staticmethod
    def _secret_text_row(field: QTextEdit, button: QPushButton) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(field)
        row.addWidget(button)
        return holder

    def _make_line_secret_toggle(self, field: QLineEdit) -> QPushButton:
        button = QPushButton("Show")
        button.setCheckable(True)

        def toggle(checked: bool) -> None:
            field.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
            button.setText(self._tr("hide") if checked else self._tr("show"))

        button.toggled.connect(toggle)
        return button

    def _toggle_private_key_visibility(self, visible: bool) -> None:
        self.ce_ssh_private_key.setStyleSheet("" if visible else "font-family: monospace;")
        self.ce_ssh_private_key.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextEditorInteraction if visible else Qt.TextInteractionFlag.TextSelectableByMouse
        )
        if visible:
            stored = self.ce_ssh_private_key.property("_secret_plain_text")
            self.ce_ssh_private_key.setPlainText(str(stored or ""))
            self.ce_ssh_private_key_toggle.setText(self._tr("hide"))
            return

        self._hide_private_key_in_widget()

    def _hide_private_key_in_widget(self) -> None:
        plain = str(self.ce_ssh_private_key.property("_secret_plain_text") or self.ce_ssh_private_key.toPlainText() or "")
        self.ce_ssh_private_key.setProperty("_secret_plain_text", plain)
        self.ce_ssh_private_key.setPlainText(mask_secret(plain) if plain else "")
        self.ce_ssh_private_key_toggle.setText(self._tr("show"))

    def set_secret_text_hidden(self, widget: QTextEdit, plain_text: str) -> None:
        if widget is not self.ce_ssh_private_key:
            return
        widget.setProperty("_secret_plain_text", plain_text)
        if self.ce_ssh_private_key_toggle.isChecked():
            self.ce_ssh_private_key_toggle.blockSignals(True)
            self.ce_ssh_private_key_toggle.setChecked(False)
            self.ce_ssh_private_key_toggle.blockSignals(False)
        self._hide_private_key_in_widget()

    def reset_secret_visibility(self) -> None:
        self.show_passwords = False
        self.ce_password_toggle.setChecked(False)
        self.ce_ssh_passphrase_toggle.setChecked(False)
        if self.ce_ssh_private_key_toggle.isChecked():
            self.ce_ssh_private_key_toggle.setChecked(False)
        else:
            self._hide_private_key_in_widget()
        self._details_secrets_visible = False
        self._apply_secret_toggle_labels()

    def clear_sensitive_fields(self) -> None:
        self._clear_credential_editor()
        self.details_table.setRowCount(0)
        self._details_rows = []
        self.reset_secret_visibility()

    def eventFilter(self, obj, event):  # noqa: N802
        if event and event.type() in (
            QEvent.Type.MouseMove,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseButtonRelease,
            QEvent.Type.KeyPress,
            QEvent.Type.KeyRelease,
            QEvent.Type.Wheel,
            QEvent.Type.FocusIn,
        ):
            self._reset_auto_lock_timer()
        return super().eventFilter(obj, event)

    def _reset_auto_lock_timer(self) -> None:
        if hasattr(self, "_auto_lock_timer") and not self._auto_lock_in_progress:
            self._auto_lock_timer.start(config.AUTO_LOCK_TIMEOUT_MS)

    def _clear_sensitive_data(self) -> None:
        old_key = self.encryption_key
        self.encryption_key = b""
        self.all_credentials = []
        self.filtered_credentials = []
        self._clear_clipboard_if_ours(force=True)
        self._stop_clipboard_cleanup_timer()
        self.search_service.clear_index()
        self.vault_service.clear_decrypted_cache()
        self.clear_sensitive_fields()
        self.search_input.clear()
        self.table.clearSelection()
        self.tree.clearSelection()
        for dialog in self.findChildren(CredentialDialog):
            dialog._reset_secret_visibility()
            dialog.close()
        del old_key
        gc.collect()

    def _auto_lock(self) -> None:
        if self._auto_lock_in_progress or self._quit_requested:
            return
        self._auto_lock_in_progress = True
        if hasattr(self, "_auto_lock_timer"):
            self._auto_lock_timer.stop()
        self._clear_sensitive_data()
        self.hide()
        QMessageBox.information(None, "Vault locked", "Vault was auto-locked due to inactivity.")
        if callable(self._on_lock):
            self._on_lock()
        self._auto_lock_in_progress = False

    def _apply_tray_language(self) -> None:
        if hasattr(self, "tray_open_action"):
            self.tray_open_action.setText(self._tr("tray_open"))
            self.tray_exit_action.setText(self._tr("tray_exit"))

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._restore_from_tray()

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.activateWindow()
        self.raise_()
        self._reset_auto_lock_timer()

    def _exit_from_tray(self) -> None:
        self._quit_requested = True
        if hasattr(self, "_auto_lock_timer"):
            self._auto_lock_timer.stop()
        app = QApplication.instance()
        if app:
            app.removeEventFilter(self)
        self.tray_icon.hide()
        QApplication.instance().quit()

    def closeEvent(self, event) -> None:
        if self._quit_requested:
            app = QApplication.instance()
            if app:
                app.removeEventFilter(self)
            event.accept()
            return
        self.hide()
        self.tray_icon.showMessage(
            config.APP_NAME,
            self._tr("tray_msg"),
            QSystemTrayIcon.MessageIcon.Information,
            2500,
        )
        event.ignore()

    def refresh_all(self) -> None:
        self.reset_secret_visibility()
        self.orgs = self.vault_service.list_organizations()
        self.groups = self.vault_service.list_groups()
        self.devices = self.vault_service.list_devices()
        self.all_credentials = self.vault_service.load_credentials_decrypted(self.encryption_key)
        self.search_service.build_index(self.all_credentials)
        self._build_tree()
        self.apply_search()

    def _build_tree(self) -> None:
        self.tree.clear()
        children_map: dict[int | None, list[dict[str, Any]]] = {}
        for g in self.groups:
            children_map.setdefault(g.get("parent_group_id"), []).append(g)

        devices_by_group: dict[int, list[dict[str, Any]]] = {}
        for d in self.devices:
            devices_by_group.setdefault(d["group_id"], []).append(d)

        def add_group_node(parent: QTreeWidgetItem, group: dict[str, Any]) -> None:
            item = QTreeWidgetItem([f"[{self._tr('group_prefix')}] {group['name']}"])
            item.setData(0, Qt.ItemDataRole.UserRole, {"kind": "group", "id": group["id"], "organization_id": group["organization_id"]})
            parent.addChild(item)

            for sub in sorted(children_map.get(group["id"], []), key=lambda x: x["name"].lower()):
                add_group_node(item, sub)

            for dev in sorted(devices_by_group.get(group["id"], []), key=lambda x: x["name"].lower()):
                d_item = QTreeWidgetItem([f"[{self._tr('device_prefix')}] {dev['name']}"])
                d_item.setData(
                    0,
                    Qt.ItemDataRole.UserRole,
                    {"kind": "device", "id": dev["id"], "organization_id": dev["organization_id"], "group_id": group["id"]},
                )
                item.addChild(d_item)

        roots = children_map.get(None, [])
        for org in sorted(self.orgs, key=lambda x: x["name"].lower()):
            o_item = QTreeWidgetItem([f"[{self._tr('org_prefix')}] {org['name']}"])
            o_item.setData(0, Qt.ItemDataRole.UserRole, {"kind": "organization", "id": org["id"]})
            self.tree.addTopLevelItem(o_item)
            for g in sorted([x for x in roots if x["organization_id"] == org["id"]], key=lambda x: x["name"].lower()):
                add_group_node(o_item, g)
            o_item.setExpanded(True)

    def _selected_scope(self) -> dict[str, Any] | None:
        item = self.tree.currentItem()
        if not item:
            return None
        return item.data(0, Qt.ItemDataRole.UserRole)

    def apply_search(self) -> None:
        self.show_passwords = False
        data = self.search_service.filter_credentials(self.all_credentials, self.search_input.text())
        scope = self._selected_scope()
        if scope:
            if scope["kind"] == "organization":
                data = [c for c in data if c.organization_id == scope["id"]]
            elif scope["kind"] == "group":
                data = [c for c in data if c.group_id == scope["id"]]
            elif scope["kind"] == "device":
                data = [c for c in data if c.device_id == scope["id"]]
        self.filtered_credentials = data
        self._render_table()
        self._update_right_panel(scope)

    def _render_table(self) -> None:
        self.table.setRowCount(len(self.filtered_credentials))
        for i, c in enumerate(self.filtered_credentials):
            username = str(c.payload.get("username", ""))
            password = str(c.payload.get("password", ""))
            pass_value = ("*" * len(password) if password else "")
            vals = [
                c.organization_name or "",
                c.group_name or "",
                c.device_name or "",
                c.cred_type or "",
                c.environment or "",
                username,
                pass_value,
            ]
            for col, val in enumerate(vals):
                self.table.setItem(i, col, QTableWidgetItem(val))
        self.table.resizeColumnsToContents()
        self.status.setText(self._tr("status_credentials").format(count=len(self.filtered_credentials)))

    def _selected_credential(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.filtered_credentials):
            return None
        return self.filtered_credentials[row]

    def _find_device(self, device_id: int) -> dict[str, Any] | None:
        return next((d for d in self.devices if d["id"] == device_id), None)

    def _find_group(self, group_id: int) -> dict[str, Any] | None:
        return next((g for g in self.groups if g["id"] == group_id), None)

    def _update_right_panel(self, scope: dict[str, Any] | None) -> None:
        if not scope or scope.get("kind") != "device":
            self.device_editor_widget.hide()
            self.cred_editor_widget.hide()
            self.details_panel.hide()
            self.list_panel.show()
            self.device_context_label.clear()
            self.device_context_label.hide()
            self._current_device_cred_id = None
            self._device_edit_mode = False
            self._details_open = False
            self.clear_sensitive_fields()
            return

        device = self._find_device(scope["id"])
        if not device:
            self.device_editor_widget.hide()
            self.cred_editor_widget.hide()
            self.details_panel.hide()
            self.list_panel.show()
            self.device_context_label.clear()
            self.device_context_label.hide()
            self._current_device_cred_id = None
            self.clear_sensitive_fields()
            return

        self.device_context_label.show()
        self.device_context_label.setText(self._tr("selected_device").format(name=device["name"]))
        self.device_editor_widget.hide()
        self.cred_editor_widget.hide()
        self.details_panel.setVisible(self._details_open)
        self.list_panel.setVisible(not self._details_open)
        self._updating_device_form = True
        self.device_name_input.setText(device["name"])
        self.device_group_combo.clear()

        group_items = [g for g in self.groups if g["organization_id"] == device["organization_id"]]
        for g in group_items:
            self.device_group_combo.addItem(g["name"], g["id"])
        for i in range(self.device_group_combo.count()):
            if self.device_group_combo.itemData(i) == device["group_id"]:
                self.device_group_combo.setCurrentIndex(i)
                break
        self._updating_device_form = False

        if self.filtered_credentials:
            if self.table.currentRow() < 0:
                self.table.selectRow(0)
            if self._details_open:
                self._fill_details_table_from_selected()
        else:
            self._current_device_cred_id = None
            self._clear_credential_editor()
            self.details_table.setRowCount(0)
            self._details_rows = []

    def _apply_device_edit_mode(self) -> None:
        self.device_editor_widget.hide()
        self.cred_editor_widget.hide()
        self.details_panel.setVisible(self._details_open)

    def save_selected_device(self) -> None:
        if not self._device_edit_mode:
            QMessageBox.information(self, "Device", "Press Edit first to enable changes.")
            return
        if self._updating_device_form:
            return
        scope = self._selected_scope()
        if not scope or scope.get("kind") != "device":
            QMessageBox.information(self, "Device", "Select device in hierarchy first.")
            return
        device = self._find_device(scope["id"])
        if not device:
            QMessageBox.warning(self, "Device", "Device not found.")
            return

        new_name = self.device_name_input.text().strip()
        new_group_id = self.device_group_combo.currentData()
        if not new_name:
            QMessageBox.warning(self, "Validation", "Device name is required.")
            return
        if new_group_id is None:
            QMessageBox.warning(self, "Validation", "Group is required.")
            return

        self.vault_service.update_device(
            device_id=device["id"],
            organization_id=device["organization_id"],
            group_id=int(new_group_id),
            name=new_name,
        )
        self.refresh_all()
        self._select_tree_device(device["id"])
        self._device_edit_mode = False
        self._apply_device_edit_mode()

    def _select_tree_device(self, device_id: int) -> None:
        def walk(item: QTreeWidgetItem) -> QTreeWidgetItem | None:
            data = item.data(0, Qt.ItemDataRole.UserRole)
            if data and data.get("kind") == "device" and data.get("id") == device_id:
                return item
            for i in range(item.childCount()):
                found = walk(item.child(i))
                if found:
                    return found
            return None

        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            found = walk(top)
            if found:
                self.tree.setCurrentItem(found)
                found.setSelected(True)
                parent = found.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
                return

    def on_table_selection_changed(self) -> None:
        try:
            self.reset_secret_visibility()
            scope = self._selected_scope()
            if scope and scope.get("kind") == "device":
                self._fill_credential_editor_from_selected()
                self._fill_details_table_from_selected()
        except Exception as exc:
            self._report_ui_error("Table selection changed", exc)

    def on_table_cell_clicked(self, row: int, column: int) -> None:
        try:
            _ = row, column
            self.reset_secret_visibility()
            scope = self._selected_scope()
            if scope and scope.get("kind") == "device":
                self._fill_credential_editor_from_selected()
                self._fill_details_table_from_selected()
        except Exception as exc:
            self._report_ui_error("Table cell clicked", exc)

    def open_table_context_menu(self, pos) -> None:
        row = self.table.rowAt(pos.y())
        if row >= 0:
            self.table.selectRow(row)
        selected = self._selected_credential()
        if not selected:
            return

        menu = QMenu(self)
        details_action = menu.addAction(self._tr("menu_details"))
        copy_login_action = menu.addAction(self._tr("copy_login"))
        copy_password_action = menu.addAction(self._tr("copy_password"))
        action = menu.exec(self.table.viewport().mapToGlobal(pos))

        if action == details_action:
            self.open_details_for_credential(selected)
        elif action == copy_login_action:
            self._copy_to_clipboard(str(selected.payload.get("username", "")))
        elif action == copy_password_action:
            self._copy_to_clipboard(str(selected.payload.get("password", "")), sensitive=True)

    def open_details_for_credential(self, credential) -> None:
        try:
            if credential.device_id is None:
                QMessageBox.information(self, "Details", "Credential is not attached to a device.")
                return
            self._details_open = True
            self._device_edit_mode = False
            self.search_input.clear()
            self._select_tree_device(credential.device_id)
            self.apply_search()
            for idx, item in enumerate(self.filtered_credentials):
                if item.id == credential.id:
                    self.table.selectRow(idx)
                    break
            self._details_secrets_visible = False
            self._fill_details_table_from_selected()
            self.details_panel.show()
            self.cred_editor_widget.hide()
            self.status.setText(self._tr("status_details_opened"))
        except Exception as exc:
            self._report_ui_error("Open details for credential", exc)

    def _clear_credential_editor(self) -> None:
        self.reset_secret_visibility()
        self.ce_type.setCurrentIndex(0)
        self.ce_env.setCurrentIndex(0)
        self.ce_username.clear()
        self.ce_password.clear()
        self.ce_host.clear()
        self.ce_ip.clear()
        self.ce_port.clear()
        self.ce_url.clear()
        self.ce_ssh_user.clear()
        self.ce_ssh_key_path.clear()
        self.set_secret_text_hidden(self.ce_ssh_private_key, "")
        self.ce_ssh_passphrase.clear()
        self.ce_notes.clear()
        self.ce_tags.clear()
        self.ce_extra.clear()

    def _fill_details_table_from_selected(self) -> None:
        selected = self._selected_credential()
        if not selected:
            self.details_table.setRowCount(0)
            self._details_rows = []
            return
        payload = selected.payload or {}
        self._details_rows = [
            ("type", selected.cred_type or ""),
            ("environment", selected.environment or ""),
            ("username", str(payload.get("username", ""))),
            ("password", str(payload.get("password", ""))),
            ("host", str(payload.get("host", ""))),
            ("ip", str(payload.get("ip", ""))),
            ("port", str(payload.get("port", ""))),
            ("url", str(payload.get("url", ""))),
            ("ssh_user", str(payload.get("ssh_user", ""))),
            ("ssh_key_path", str(payload.get("ssh_key_path", ""))),
            ("ssh_private_key", str(payload.get("ssh_private_key", ""))),
            ("ssh_passphrase", str(payload.get("ssh_passphrase", ""))),
            ("notes", str(payload.get("notes", ""))),
            ("tags", selected.tags or ""),
            ("extra", str(payload.get("extra", ""))),
        ]
        self._render_details_rows()

    def _render_details_rows(self) -> None:
        self.details_table.clearContents()
        self.details_table.setRowCount(len(self._details_rows))
        for i, (k, v) in enumerate(self._details_rows):
            key_item = QTableWidgetItem(k)
            key_item.setFlags(key_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.details_table.setItem(i, 0, key_item)
            visible_value = v if (self._details_secrets_visible or not is_secret_field_name(k)) else mask_secret(v)
            value_widget = QLabel(visible_value)
            value_widget.setToolTip(visible_value[:2000])
            value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value_widget.setWordWrap(False)
            value_widget.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            value_widget.setContentsMargins(2, 0, 2, 0)
            self.details_table.setCellWidget(i, 1, value_widget)
            line_count = max(1, min(4, visible_value.count("\n") + 1))
            self.details_table.setRowHeight(i, 32 + (line_count - 1) * 18)
        self._apply_secret_toggle_labels()

    def _toggle_details_secrets_visibility(self) -> None:
        self._details_secrets_visible = not self._details_secrets_visible
        self._render_details_rows()

    def open_details_context_menu(self, pos) -> None:
        row = self.details_table.rowAt(pos.y())
        col = self.details_table.columnAt(pos.x())
        if row >= 0 and col >= 0:
            self.details_table.setCurrentCell(row, col)
        menu = QMenu(self)
        copy_row_action = menu.addAction(self._tr("copy_row"))
        copy_all_action = menu.addAction(self._tr("copy_all"))
        chosen = menu.exec(self.details_table.viewport().mapToGlobal(pos))
        if chosen == copy_row_action:
            self.copy_selected_detail_row()
        elif chosen == copy_all_action:
            self.copy_all_details()

    def copy_selected_detail_row(self) -> None:
        item = self.details_table.currentItem()
        if not item:
            return
        row = item.row()
        key_item = self.details_table.item(row, 0)
        value_text = self._detail_value_text(row)
        if key_item and value_text is not None:
            self._copy_to_clipboard(f"{key_item.text()}: {value_text}")
            self.status.setText(self._tr("status_details_copied"))

    def copy_all_details(self) -> None:
        lines = []
        for row in range(self.details_table.rowCount()):
            key_item = self.details_table.item(row, 0)
            value_text = self._detail_value_text(row)
            if key_item and value_text is not None:
                lines.append(f"{key_item.text()}: {value_text}")
        if lines:
            self._copy_to_clipboard("\n".join(lines))
            self.status.setText(self._tr("status_details_copied"))

    def _detail_value_text(self, row: int) -> str | None:
        if row < 0 or row >= len(self._details_rows):
            return None
        key, value = self._details_rows[row]
        if not self._details_secrets_visible and is_secret_field_name(key):
            return mask_secret(value)
        return value

    def _fill_credential_editor_from_selected(self) -> None:
        selected = self._selected_credential()
        if not selected:
            self._current_device_cred_id = None
            self._clear_credential_editor()
            return
        self._current_device_cred_id = selected.id
        self.ce_type.setCurrentText(selected.cred_type or "other")
        self.ce_env.setCurrentText(selected.environment or "other")
        self.ce_username.setText(str(selected.payload.get("username", "")))
        self.ce_password.setText(str(selected.payload.get("password", "")))
        self.ce_host.setText(str(selected.payload.get("host", "")))
        self.ce_ip.setText(str(selected.payload.get("ip", "")))
        self.ce_port.setText(str(selected.payload.get("port", "")))
        self.ce_url.setText(str(selected.payload.get("url", "")))
        self.ce_ssh_user.setText(str(selected.payload.get("ssh_user", "")))
        self.ce_ssh_key_path.setText(str(selected.payload.get("ssh_key_path", "")))
        private_key_value = str(selected.payload.get("ssh_private_key", ""))
        self.set_secret_text_hidden(self.ce_ssh_private_key, private_key_value)
        self.ce_ssh_passphrase.setText(str(selected.payload.get("ssh_passphrase", "")))
        self.ce_notes.setPlainText(str(selected.payload.get("notes", "")))
        self.ce_tags.setText(selected.tags or "")
        extra = selected.payload.get("extra", {})
        if isinstance(extra, dict):
            import json
            self.ce_extra.setPlainText(json.dumps(extra, ensure_ascii=False, indent=2))
        else:
            self.ce_extra.setPlainText(str(extra))
        self.reset_secret_visibility()

    def _is_password_reused(self, password: str, exclude_credential_id: int | None = None) -> bool:
        if not password or not self.all_credentials:
            return False
        for cred in self.all_credentials:
            if exclude_credential_id is not None and cred.id == exclude_credential_id:
                continue
            if str(cred.payload.get("password", "")) == password:
                return True
        return False

    def _confirm_reused_password_if_needed(self, password: str, exclude_credential_id: int | None = None) -> bool:
        if not self._is_password_reused(password, exclude_credential_id):
            return True
        answer = QMessageBox.question(
            self,
            "Password reuse warning",
            "This password is already used in another entry.\nDo you want to save anyway?",
        )
        return answer == QMessageBox.StandardButton.Yes

    def save_selected_device_credential(self) -> None:
        if not self._device_edit_mode:
            QMessageBox.information(self, "Credential", "Press Edit first to enable changes.")
            return
        selected = self._selected_credential()
        if not selected or self._current_device_cred_id is None:
            QMessageBox.information(self, "Credential", "Select credential row first.")
            return
        try:
            import json
            extra = self.ce_extra.toPlainText().strip()
            extra_obj = json.loads(extra) if extra else {}
            if not isinstance(extra_obj, dict):
                raise ValueError("Extra must be JSON object")
        except Exception:
            QMessageBox.warning(self, "Validation", "Extra JSON must be a valid object.")
            return

        payload = {
            "username": self.ce_username.text().strip(),
            "password": self.ce_password.text(),
            "host": self.ce_host.text().strip(),
            "ip": self.ce_ip.text().strip(),
            "port": self.ce_port.text().strip(),
            "url": self.ce_url.text().strip(),
            "ssh_user": self.ce_ssh_user.text().strip(),
            "ssh_key_path": self.ce_ssh_key_path.text().strip(),
            "ssh_private_key": self._editor_private_key_value(),
            "ssh_passphrase": self.ce_ssh_passphrase.text(),
            "notes": self.ce_notes.toPlainText(),
            "extra": extra_obj,
        }
        if not self._confirm_reused_password_if_needed(str(payload.get("password", "")), exclude_credential_id=self._current_device_cred_id):
            return
        title = payload.get("username") or payload.get("host") or payload.get("url") or "Credential"
        self.vault_service.update_credential(
            self.encryption_key,
            credential_id=self._current_device_cred_id,
            organization_id=selected.organization_id,
            group_id=selected.group_id,
            device_id=selected.device_id,
            title=str(title),
            cred_type=self.ce_type.currentText(),
            environment=self.ce_env.currentText(),
            tags=self.ce_tags.text().strip(),
            payload=payload,
        )
        self.refresh_all()
        self._select_tree_device(selected.device_id or 0)
        self._device_edit_mode = False
        self._apply_device_edit_mode()

    def copy_editor_login(self) -> None:
        self._copy_to_clipboard(self.ce_username.text())

    def copy_editor_password(self) -> None:
        self._copy_to_clipboard(self.ce_password.text(), sensitive=True)

    def copy_editor_all(self) -> None:
        if not self._confirm_copy_all_secrets():
            return
        private_key_value = self._editor_private_key_value()
        text = (
            f"type: {self.ce_type.currentText()}\n"
            f"environment: {self.ce_env.currentText()}\n"
            f"username: {self.ce_username.text()}\n"
            f"password: {self.ce_password.text()}\n"
            f"host: {self.ce_host.text()}\n"
            f"ip: {self.ce_ip.text()}\n"
            f"port: {self.ce_port.text()}\n"
            f"url: {self.ce_url.text()}\n"
            f"ssh_user: {self.ce_ssh_user.text()}\n"
            f"ssh_key_path: {self.ce_ssh_key_path.text()}\n"
            f"ssh_private_key: {private_key_value}\n"
            f"ssh_passphrase: {self.ce_ssh_passphrase.text()}\n"
            f"notes: {self.ce_notes.toPlainText()}\n"
            f"tags: {self.ce_tags.text()}\n"
            f"extra: {self.ce_extra.toPlainText()}\n"
        )
        self._copy_to_clipboard(text, sensitive=True)

    def _confirm_copy_all_secrets(self) -> bool:
        answer = QMessageBox.question(
            self,
            "Confirm copy",
            "This will copy password/private key/passphrase to clipboard. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _editor_private_key_value(self) -> str:
        if self.ce_ssh_private_key_toggle.isChecked():
            return self.ce_ssh_private_key.toPlainText()
        return str(self.ce_ssh_private_key.property("_secret_plain_text") or "")

    def add_organization(self) -> None:
        name, ok = QInputDialog.getText(self, "Add Organization", "Organization name:")
        if ok and name.strip():
            self.vault_service.add_organization(name)
            self.refresh_all()

    def add_group(self) -> None:
        if not self.orgs:
            QMessageBox.warning(self, "Missing data", "Create organization first.")
            return
        scope = self._selected_scope() or {}
        org_id = scope.get("id") if scope.get("kind") == "organization" else scope.get("organization_id")
        if not org_id:
            names = [o["name"] for o in self.orgs]
            selected, ok = QInputDialog.getItem(self, "Organization", "Select organization", names, 0, False)
            if not ok:
                return
            org_id = next(o["id"] for o in self.orgs if o["name"] == selected)
        name, ok = QInputDialog.getText(self, "Add Group/Subgroup", "Group name:")
        if ok and name.strip():
            parent_group_id = scope.get("id") if scope.get("kind") == "group" else None
            self.vault_service.add_group(org_id, name, parent_group_id)
            self.refresh_all()

    def add_device(self) -> None:
        scope = self._selected_scope()
        if not scope or scope.get("kind") != "group":
            QMessageBox.warning(self, "Selection required", "Select group/subgroup in tree first.")
            return
        name, ok = QInputDialog.getText(self, "Add Device", "Device name:")
        if ok and name.strip():
            device_id = self.vault_service.add_device(scope["organization_id"], scope["id"], name)
            self.refresh_all()
            self.add_credential(
                initial_context={
                    "organization_id": scope["organization_id"],
                    "group_id": scope["id"],
                    "device_id": device_id,
                    "type": "device",
                }
            )

    def add_credential(self, initial_context: dict[str, Any] | None = None) -> None:
        if not self.orgs:
            QMessageBox.warning(self, "Missing data", "Create organization first.")
            return
        dialog = CredentialDialog(self.orgs, self.groups, self.devices, initial=initial_context, parent=self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            return
        data = dialog.get_data()
        if not data:
            return
        if not self._confirm_reused_password_if_needed(str(data["payload"].get("password", ""))):
            return
        self.vault_service.add_credential(
            self.encryption_key,
            data["organization_id"],
            data["group_id"],
            data["device_id"],
            data["title"],
            data["type"],
            data["environment"],
            data["tags"],
            data["payload"],
        )
        self.refresh_all()

    def edit_selected(self) -> None:
        scope = self._selected_scope()
        if scope and scope.get("kind") == "device":
            if not self.filtered_credentials:
                QMessageBox.information(self, "Edit", "No credentials on selected device.")
                return
            if self.table.currentRow() < 0:
                self.table.selectRow(0)
            selected = self._selected_credential()
            if not selected:
                QMessageBox.information(self, "Edit", "Select credential first.")
                return
            initial = {
                "organization_id": selected.organization_id,
                "group_id": selected.group_id,
                "device_id": selected.device_id,
                "title": selected.title,
                "type": selected.cred_type,
                "environment": selected.environment,
                "tags": selected.tags,
                "payload": selected.payload,
            }
            dialog = CredentialDialog(self.orgs, self.groups, self.devices, initial=initial, parent=self)
            if dialog.exec() != dialog.DialogCode.Accepted:
                return
            data = dialog.get_data()
            if not data:
                return
            if not self._confirm_reused_password_if_needed(str(data["payload"].get("password", "")), exclude_credential_id=selected.id):
                return
            self.vault_service.update_credential(
                self.encryption_key,
                selected.id,
                data["organization_id"],
                data["group_id"],
                data["device_id"],
                data["title"],
                data["type"],
                data["environment"],
                data["tags"],
                data["payload"],
            )
            self.refresh_all()
            self._select_tree_device(scope["id"])
            self._details_open = True
            self.apply_search()
            return
        selected = self._selected_credential()
        if not selected:
            QMessageBox.information(self, "Edit", "Select credential first.")
            return
        initial = {
            "organization_id": selected.organization_id,
            "group_id": selected.group_id,
            "device_id": selected.device_id,
            "title": selected.title,
            "type": selected.cred_type,
            "environment": selected.environment,
            "tags": selected.tags,
            "payload": selected.payload,
        }
        dialog = CredentialDialog(self.orgs, self.groups, self.devices, initial=initial, parent=self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            return
        data = dialog.get_data()
        if not data:
            return
        if not self._confirm_reused_password_if_needed(str(data["payload"].get("password", "")), exclude_credential_id=selected.id):
            return
        self.vault_service.update_credential(
            self.encryption_key,
            selected.id,
            data["organization_id"],
            data["group_id"],
            data["device_id"],
            data["title"],
            data["type"],
            data["environment"],
            data["tags"],
            data["payload"],
        )
        self.refresh_all()

    def delete_selected(self) -> None:
        selected = self._selected_credential()
        scope = self._selected_scope()
        if selected:
            answer = QMessageBox.question(self, "Confirm delete", f"Delete credential '{selected.title}'?")
            if answer == QMessageBox.StandardButton.Yes:
                self.vault_service.delete_credential(selected.id)
                self.refresh_all()
            return
        if not scope:
            QMessageBox.information(self, "Delete", "Select item or credential first.")
            return
        label = f"{scope['kind']} #{scope['id']}"
        answer = QMessageBox.question(self, "Confirm delete", f"Delete {label}?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        if scope["kind"] == "organization":
            self.vault_service.delete_organization(scope["id"])
        elif scope["kind"] == "group":
            self.vault_service.delete_group(scope["id"])
        elif scope["kind"] == "device":
            self.vault_service.delete_device(scope["id"])
        self.refresh_all()

    def add_from_tree(self) -> None:
        scope = self._selected_scope()
        if not scope:
            choices = ["Organization", "Group/Subgroup", "Device"]
            selected, ok = QInputDialog.getItem(self, "Add", "Select entity", choices, 0, False)
            if not ok:
                return
            if selected == "Organization":
                self.add_organization()
            elif selected == "Group/Subgroup":
                self.add_group()
            elif selected == "Device":
                self.add_device()
            return

        if scope["kind"] == "organization":
            self.add_group()
        elif scope["kind"] == "group":
            picked, ok = QInputDialog.getItem(
                self,
                "Add",
                "Inside selected group:",
                ["Subgroup", "Device"],
                0,
                False,
            )
            if not ok:
                return
            if picked == "Subgroup":
                self.add_group()
            else:
                self.add_device()
        elif scope["kind"] == "device":
            self.add_credential()

    def edit_tree_item(self) -> None:
        scope = self._selected_scope()
        if not scope:
            QMessageBox.information(self, "Edit", "Select organization/group/device in tree first.")
            return

        old_name = ""
        if scope["kind"] == "organization":
            old_name = next((o["name"] for o in self.orgs if o["id"] == scope["id"]), "")
        elif scope["kind"] == "group":
            old_name = next((g["name"] for g in self.groups if g["id"] == scope["id"]), "")
        elif scope["kind"] == "device":
            self.edit_selected()
            return

        name, ok = QInputDialog.getText(self, "Rename", "New name:", text=old_name)
        if not ok or not name.strip():
            return

        if scope["kind"] == "organization":
            self.vault_service.rename_organization(scope["id"], name)
        elif scope["kind"] == "group":
            self.vault_service.rename_group(scope["id"], name)
        self.refresh_all()

    def delete_tree_item(self) -> None:
        scope = self._selected_scope()
        if not scope:
            QMessageBox.information(self, "Delete", "Select organization/group/device in tree first.")
            return

        label = f"{scope['kind']} #{scope['id']}"
        answer = QMessageBox.question(self, "Confirm delete", f"Delete {label}?")
        if answer != QMessageBox.StandardButton.Yes:
            return

        if scope["kind"] == "organization":
            self.vault_service.delete_organization(scope["id"])
        elif scope["kind"] == "group":
            self.vault_service.delete_group(scope["id"])
        elif scope["kind"] == "device":
            self.vault_service.delete_device(scope["id"])
        self.refresh_all()

    def open_tree_context_menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        if item:
            self.tree.setCurrentItem(item)
            scope = item.data(0, Qt.ItemDataRole.UserRole)
        else:
            scope = self._selected_scope()

        menu = QMenu(self)
        details_action = None
        add_org_action = menu.addAction(self._tr("menu_add_org"))
        menu.addSeparator()
        if scope and scope.get("kind") == "device":
            details_action = menu.addAction(self._tr("menu_details"))
            menu.addSeparator()
        add_action = menu.addAction(self._tr("menu_add"))
        edit_action = menu.addAction(self._tr("menu_edit"))
        delete_action = menu.addAction(self._tr("menu_delete"))
        selected = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if selected == add_org_action:
            self.add_organization()
        elif details_action and selected == details_action:
            self.show_selected_device_details()
        elif selected == add_action:
            self.add_from_tree()
        elif selected == edit_action:
            self.edit_tree_item()
        elif selected == delete_action:
            self.delete_tree_item()

    def on_tree_item_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        _ = column
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data and data.get("kind") == "device":
            self.show_selected_device_details()

    def show_selected_device_details(self) -> None:
        scope = self._selected_scope()
        if not scope or scope.get("kind") != "device":
            QMessageBox.information(self, "Details", "Select device in hierarchy first.")
            return
        self._details_open = True
        self._device_edit_mode = False
        self.search_input.clear()
        self.apply_search()
        self.details_panel.show()
        self.cred_editor_widget.hide()
        self._details_secrets_visible = False
        try:
            if self.filtered_credentials:
                self.table.selectRow(0)
                self._fill_details_table_from_selected()
                self.status.setText(self._tr("status_details_opened"))
            else:
                self.details_table.setRowCount(0)
                self._details_rows = []
                self.status.setText(self._tr("status_no_device_credentials"))
        except Exception as exc:
            self._report_ui_error("Open details", exc)

    def copy_login(self) -> None:
        selected = self._selected_credential()
        if not selected:
            QMessageBox.information(self, "Copy", "Select credential first.")
            return
        self._copy_to_clipboard(str(selected.payload.get("username", "")))

    def copy_password(self) -> None:
        selected = self._selected_credential()
        if not selected:
            QMessageBox.information(self, "Copy", "Select credential first.")
            return
        self._copy_to_clipboard(str(selected.payload.get("password", "")), sensitive=True)

    def _clear_clipboard_if_ours(self, force: bool = False) -> None:
        clipboard = QApplication.clipboard()
        if not self._clipboard_secret_fingerprint:
            return
        current = clipboard.text()
        current_fp = hashlib.sha256(current.encode("utf-8")).hexdigest() if current else ""
        current_matches = current_fp == self._clipboard_secret_fingerprint
        current_matches_value = bool(self._clipboard_secret_value) and current == self._clipboard_secret_value
        if current_matches or current_matches_value:
            clipboard.clear()
            self.status.setText(self._tr("status_clipboard_cleared"))
        elif not force:
            return
        self._clipboard_secret_fingerprint = None
        self._clipboard_secret_value = None
        self._stop_clipboard_cleanup_timer()

    def _stop_clipboard_cleanup_timer(self) -> None:
        if self._clipboard_clear_timer and self._clipboard_clear_timer.isActive():
            self._clipboard_clear_timer.stop()

    def _copy_to_clipboard(self, value: str, sensitive: bool = False) -> None:
        clipboard = QApplication.clipboard()
        clipboard.setText(value)
        self.status.setText(self._tr("status_copied"))
        if not sensitive:
            return

        self._clipboard_secret_value = value
        self._clipboard_secret_fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""
        if self._clipboard_clear_timer is None:
            self._clipboard_clear_timer = QTimer(self)
            self._clipboard_clear_timer.setSingleShot(True)
            self._clipboard_clear_timer.timeout.connect(self._clear_clipboard_if_ours)
        self._clipboard_clear_timer.start(45_000)

    def toggle_password_visibility(self) -> None:
        self.show_passwords = False
        self._render_table()

    def open_settings(self) -> None:
        action, ok = QInputDialog.getItem(
            self,
            self._tr("dialog_settings"),
            self._tr("dialog_select_action"),
            [self._tr("action_change_master"), self._tr("action_export_backup")],
            0,
            False,
        )
        if not ok:
            return
        if action == self._tr("action_change_master"):
            self._change_master_password()
        elif action == self._tr("action_export_backup"):
            self._export_database_backup()

    def show_app_info(self) -> None:
        QMessageBox.information(
            self,
            self._tr("about_title"),
            self._tr("about_text").format(version=config.APP_VERSION),
        )

    def _change_master_password(self) -> None:
        dialog = ChangeMasterPasswordDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        old_password = dialog.old_password.text()
        new_password = dialog.new_password.text()
        confirm_password = dialog.confirm_password.text()

        if not new_password:
            QMessageBox.warning(self, "Validation", "New password cannot be empty.")
            return
        if new_password != confirm_password:
            QMessageBox.warning(self, "Validation", "New passwords do not match.")
            return

        new_key = self.vault_service.change_master_password(old_password, new_password)
        if not new_key:
            QMessageBox.critical(self, "Error", "Current master password is incorrect.")
            return

        self.encryption_key = new_key
        self.refresh_all()
        QMessageBox.information(self, "Success", "Master password changed.")

    def _export_database_backup(self) -> None:
        source = Path(config.DB_PATH)
        if not source.exists():
            QMessageBox.warning(self, "Backup", "Database file was not found.")
            return

        destination_dir = QFileDialog.getExistingDirectory(self, "Select backup destination")
        if not destination_dir:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"password_vault_backup_{timestamp}.db"
        destination = Path(destination_dir) / backup_name

        try:
            with sqlite3.connect(source) as source_conn:
                with sqlite3.connect(destination) as destination_conn:
                    source_conn.backup(destination_conn)
                    destination_conn.commit()
        except Exception as exc:
            QMessageBox.critical(self, "Backup failed", f"Could not create backup:\n{exc}")
            return

        QMessageBox.information(self, "Backup created", f"Encrypted DB backup created:\n{destination}")


    def _report_ui_error(self, context: str, exc: Exception) -> None:
        try:
            log_path = Path(config.DB_PATH).resolve().parent / "ui_errors.log"
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat()}] {context}: {exc}\n")
        except Exception:
            pass
        QMessageBox.critical(self, "UI error", f"{context} failed:\n{exc}")
