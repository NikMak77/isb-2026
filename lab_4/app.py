from __future__ import annotations

import os
import sys
from pathlib import Path

from constants import (
    GUI_WINDOW_TITLE, GUI_MESSAGE_LABEL, GUI_KEY_LABEL,
    GUI_GENERATE_BTN, GUI_VERIFY_BTN, GUI_TAMPER_BTN,
    GUI_STATUS_WAITING, GUI_STATUS_GENERATED, GUI_STATUS_AUTH_OK,
    GUI_STATUS_AUTH_FAIL, GUI_STATUS_TAMPERED,
    GUI_ERROR_EMPTY, GUI_ERROR_NO_HMAC, GUI_ERROR_EMPTY_TAMPER
)

def configure_qt_plugin_paths() -> None:
    try:
        from PyQt5.QtCore import QLibraryInfo
    except ImportError:
        return
    plugins_path = QLibraryInfo.location(QLibraryInfo.PluginsPath)
    platforms_path = str(Path(plugins_path) / "platforms") if plugins_path else ""
    if plugins_path:
        os.environ["QT_PLUGIN_PATH"] = plugins_path
    if platforms_path:
        os.environ["QT_QPA_PLATFORM_PLUGIN_PATH"] = platforms_path

configure_qt_plugin_paths()

from PyQt5.QtWidgets import (
    QApplication, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QTextEdit, QVBoxLayout, QWidget,
)
from hmac_utils import compute_hmac, verify_hmac, tamper_message


class HMACTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout()
        self.current_hmac: str | None = None

        self.message_label = QLabel(GUI_MESSAGE_LABEL)
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(100)

        self.key_label = QLabel(GUI_KEY_LABEL)
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)

        self.generate_btn = QPushButton(GUI_GENERATE_BTN)
        self.verify_btn = QPushButton(GUI_VERIFY_BTN)
        self.tamper_btn = QPushButton(GUI_TAMPER_BTN)

        self.result_display = QLineEdit()
        self.result_display.setReadOnly(True)
        self.status_label = QLabel(GUI_STATUS_WAITING)

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
        try:
            msg = self.message_input.toPlainText()
            key = self.key_input.text()
            if not msg or not key:
                raise ValueError(GUI_ERROR_EMPTY)
            self.current_hmac = compute_hmac(msg, key)
            self.result_display.setText(self.current_hmac)
            self.status_label.setText(GUI_STATUS_GENERATED)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_verify(self) -> None:
        try:
            if self.current_hmac is None:
                raise ValueError(GUI_ERROR_NO_HMAC)
            msg = self.message_input.toPlainText()
            key = self.key_input.text()
            if not msg or not key:
                raise ValueError(GUI_ERROR_EMPTY)
            valid = verify_hmac(msg, key, self.current_hmac)
            if valid:
                self.status_label.setText(GUI_STATUS_AUTH_OK)
            else:
                self.status_label.setText(GUI_STATUS_AUTH_FAIL)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_tamper(self) -> None:
        try:
            original = self.message_input.toPlainText()
            if not original:
                raise ValueError(GUI_ERROR_EMPTY_TAMPER)
            tampered = tamper_message(original)
            self.message_input.setPlainText(tampered)
            self.status_label.setText(GUI_STATUS_TAMPERED)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(GUI_WINDOW_TITLE)
        self.setCentralWidget(HMACTab())


def run_gui() -> None:
    try:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Failed to start GUI: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run_gui()