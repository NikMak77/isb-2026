from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any, Optional


def configure_qt_plugin_paths() -> None:
    """
    Configure Qt plugin paths before importing PyQt5 widgets.
    Forces correct paths even if environment variables are empty/misconfigured.

    Returns:
        None.
    """
    try:
        from PyQt5.QtCore import QLibraryInfo
    except ImportError:
        return

    plugins_path = QLibraryInfo.location(QLibraryInfo.PluginsPath)
    platforms_path = str(Path(plugins_path) / "platforms") if plugins_path else ""

    match (plugins_path, platforms_path):
        case (str(path), _) if path:
            os.environ["QT_PLUGIN_PATH"] = path
        case _:
            pass

    match (platforms_path,):
        case (str(path),) if path:
            os.environ["QT_QPA_PLATFORM_PLUGIN_PATH"] = path
        case _:
            pass

configure_qt_plugin_paths()

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from constants import (
    COLLISION_LIMIT_GUI,
    COLLISION_MAX_BITS,
    COLLISION_MIN_BITS,
    GUI_DEFAULT_BITS,
    GUI_PROGRESS_UPDATE_INTERVAL,
)
from hmac_utils import compute_hmac, verify_hmac, tamper_message
from settings_loader import load_settings

SETTINGS = load_settings()

class WorkerThread(QThread):
    """Worker thread for collision search to keep GUI responsive."""

    progress = pyqtSignal(int, int)
    result = pyqtSignal(object)

    def __init__(self, bits: int, max_attempts: int) -> None:
        super().__init__()
        self.bits = bits
        self.max_attempts = max_attempts

    def run(self) -> None:
        """Search for collision, emit progress and result signals."""
        seen: dict[int, bytes] = {}
        update_interval = SETTINGS['gui']['progress_update_interval']

        for i in range(self.max_attempts):
            try:
                match i % update_interval:
                    case 0:
                        self.progress.emit(i, self.max_attempts)

                msg = os.urandom(16)
                full = hashlib.sha256(msg).digest()
                byte_count = (self.bits + 7) // 8
                truncated = int.from_bytes(full[:byte_count], 'big')
                match self.bits % 8:
                    case 0:
                        pass
                    case _:
                        truncated >>= (8 - self.bits % 8)

                match truncated:
                    case _ if truncated in seen:
                        self.result.emit((seen[truncated], msg, truncated))
                        return
                    case _:
                        seen[truncated] = msg
            except Exception:
                self.result.emit(None)
                return

        self.result.emit(None)


class HMACTab(QWidget):
    """Tab for HMAC generation, verification, and tamper demonstration."""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout()
        self.current_hmac: Optional[str] = None

        self.message_label = QLabel("Message:")
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(100)

        self.key_label = QLabel("Secret key:")
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)

        self.generate_btn = QPushButton("Compute HMAC")
        self.verify_btn = QPushButton("Verify HMAC")
        self.tamper_btn = QPushButton("Tamper message")

        self.result_display = QLineEdit()
        self.result_display.setReadOnly(True)
        self.status_label = QLabel("Status: waiting...")

        layout.addWidget(self.message_label)
        layout.addWidget(self.message_input)
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)
        layout.addWidget(self.generate_btn)
        layout.addWidget(self.verify_btn)
        layout.addWidget(self.tamper_btn)
        layout.addWidget(self.result_display)
        layout.addWidget(self.status_label)
        self.setLayout(layout)

        self.generate_btn.clicked.connect(self.on_generate)
        self.verify_btn.clicked.connect(self.on_verify)
        self.tamper_btn.clicked.connect(self.on_tamper)

    def on_generate(self) -> None:
        """Compute HMAC from current message and key."""
        try:
            msg = self.message_input.toPlainText()
            key = self.key_input.text()

            match (msg, key):
                case ("", _) | (_, ""):
                    raise ValueError("Message and key cannot be empty.")
                case (str(m), str(k)):
                    self.current_hmac = compute_hmac(m, k)
                    self.result_display.setText(self.current_hmac)
                    self.status_label.setText("HMAC generated. Ready to verify.")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_verify(self) -> None:
        """Verify HMAC of current message against stored HMAC."""
        try:
            match self.current_hmac:
                case None:
                    raise ValueError("Generate HMAC first.")
                case str():

                    msg = self.message_input.toPlainText()
                    key = self.key_input.text()

                    match (msg, key):
                        case ("", _) | (_, ""):
                            raise ValueError("Message and key cannot be empty.")
                        case (str(m), str(k)):
                            valid = verify_hmac(m, k, self.current_hmac)

                            match valid:
                                case True:
                                    self.status_label.setText(
                                        "Authenticity confirmed (HMAC matches)"
                                    )
                                case False:
                                    self.status_label.setText(
                                        "HMAC mismatch! Message or key modified."
                                    )

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_tamper(self) -> None:
        """Tamper with the message to demonstrate detection."""
        try:
            original = self.message_input.toPlainText()

            match original:
                case "":
                    raise ValueError("Message is empty, nothing to tamper.")
                case str(o):
                    tampered = tamper_message(o)
                    self.message_input.setPlainText(tampered)
                    self.status_label.setText(
                        "Message tampered! Click 'Verify HMAC'."
                    )

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


class CollisionTab(QWidget):
    """Tab for collision search with progress bar."""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout()

        self.bits_label = QLabel("Truncation bits:")
        self.bits_spin = QSpinBox()
        self.bits_spin.setRange(COLLISION_MIN_BITS, COLLISION_MAX_BITS)
        self.bits_spin.setValue(SETTINGS['gui']['default_bits'])

        self.search_btn = QPushButton("Find collision")

        self.progress_bar = QProgressBar()

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        layout.addWidget(self.bits_label)
        layout.addWidget(self.bits_spin)
        layout.addWidget(self.search_btn)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.result_text)
        self.setLayout(layout)

        self.search_btn.clicked.connect(self.on_search)

    def on_search(self) -> None:
        """Start collision search in a separate thread."""
        self.search_btn.setEnabled(False)
        self.result_text.clear()
        self.progress_bar.setValue(0)

        bits = self.bits_spin.value()
        max_attempts = SETTINGS['collision']['limit_gui']

        self.worker = WorkerThread(bits, max_attempts)
        self.worker.progress.connect(self.update_progress)
        self.worker.result.connect(self.on_finished)
        self.worker.start()

    def update_progress(self, current: int, total: int) -> None:
        """Update progress bar."""
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)

    def on_finished(self, result: Any) -> None:
        """Handle search completion."""
        self.search_btn.setEnabled(True)

        match result:
            case None:
                self.result_text.append("Collision not found within limit.")
            case tuple((m1, m2, h)) if len(result) == 3:
                self.result_text.append("Collision found!")
                self.result_text.append(f"Message 1 (hex): {m1.hex()}")
                self.result_text.append(f"Message 2 (hex): {m2.hex()}")
                self.result_text.append(f"Truncated hash: {hex(h)}")
            case _:
                self.result_text.append("Unexpected error occurred.")


class MainWindow(QMainWindow):
    """Main application window with tabs."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Lab 4 – Hash Functions and HMAC")

        tabs = QTabWidget()
        self.hmac_tab = HMACTab()
        self.collision_tab = CollisionTab()

        tabs.addTab(self.hmac_tab, "HMAC")
        tabs.addTab(self.collision_tab, "Collisions")

        self.setCentralWidget(tabs)


def run_gui() -> None:
    """Launch the PyQt5 application."""
    try:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        match e:
            case Exception():
                print(f"Failed to start GUI: {e}", file=sys.stderr)
                sys.exit(1)


if __name__ == "__main__":
    run_gui()