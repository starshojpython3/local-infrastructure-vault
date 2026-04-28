import os
import sys
import ctypes
import traceback
from pathlib import Path

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from app.database import Database
from app.storage_setup import resolve_storage_root
from app.ui.login_window import LoginWindow
from app.ui.main_window import MainWindow
from app.ui.theme import MODERN_QSS


def _resolve_app_icon() -> QIcon | None:
    candidates = []
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        # In packaged mode prefer explicit icon files first for stable
        # tray/taskbar rendering across Windows shells.
        candidates.append(exe_dir / "app" / "assets" / "app_icon.ico")
        candidates.append(exe_dir / "app" / "assets" / "app_icon.svg")
        candidates.append(Path(sys.executable).resolve())
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "app" / "assets" / "app_icon.ico")
            candidates.append(Path(meipass) / "app" / "assets" / "app_icon.svg")
    else:
        base = Path(__file__).resolve().parent
        candidates.append(base / "app" / "assets" / "app_icon.ico")
        candidates.append(base / "app" / "assets" / "app_icon.svg")

    for p in candidates:
        if p.exists():
            icon = QIcon(str(p))
            if not icon.isNull():
                return icon
    return None


def main() -> int:
    def _log_unhandled(exc_type, exc_value, exc_tb) -> None:
        try:
            log_path = Path(__file__).resolve().parent / "unhandled_errors.log"
            with log_path.open("a", encoding="utf-8") as f:
                f.write("=== Unhandled Exception ===\n")
                traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
                f.write("\n")
        except Exception:
            pass
        sys.__excepthook__(exc_type, exc_value, exc_tb)

    sys.excepthook = _log_unhandled
    if sys.platform.startswith("win") and os.getenv("PV_SHOW_CONSOLE") != "1":
        try:
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)
        except Exception:
            pass
    # Keep default AppUserModelID from executable/shortcut.
    # Custom IDs can cause Windows to show a generic icon in taskbar/tray
    # when the shortcut metadata does not match exactly.

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(MODERN_QSS)
    icon = _resolve_app_icon()
    if icon is not None:
        app.setWindowIcon(icon)
    storage_root = resolve_storage_root()
    if not storage_root:
        return 0
    db = Database(db_path=storage_root / "data" / "vault.db")
    db.initialize()

    login = LoginWindow(db)
    session: dict[str, MainWindow | None] = {"main": None}

    def show_login() -> None:
        main_window = session.get("main")
        if main_window:
            main_window.hide()
            main_window.deleteLater()
            session["main"] = None
        login.show()
        login.activateWindow()

    def handle_unlocked(vault_service, key) -> None:
        main_window = MainWindow(vault_service, key, on_lock=show_login)
        session["main"] = main_window
        main_window.showMaximized()

    login.unlocked.connect(handle_unlocked)
    login.show()

    if os.getenv("PV_SMOKE_TEST") == "1":
        from PyQt6.QtCore import QTimer

        QTimer.singleShot(1000, app.quit)

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
