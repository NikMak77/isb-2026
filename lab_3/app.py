import sys
import json
import os
import html
from typing import Callable, Dict

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QFormLayout, QLineEdit, QPushButton, 
                             QPlainTextEdit, QFileDialog, QMessageBox, QGroupBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont

import script
import utils


class WorkerThread(QThread):
    """Background thread for cryptographic operations."""
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, task_func: Callable, config: Dict[str, str]):
        """
        Initialize the worker thread.

        Args:
            task_func (Callable): The orchestration function to run.
            config (Dict[str, str]): Configuration dictionary.
        """
        super().__init__()
        self.task_func = task_func
        self.config = config

    def run(self) -> None:
        """Execute the task and emit signals for logging and completion."""
        try:
            self.task_func(self.config, self.log_signal.emit)
            self.finished_signal.emit(True, "Operation completed successfully.")
        except utils.CryptoAppError as e:
            self.finished_signal.emit(False, str(e))
        except Exception as e:
            self.finished_signal.emit(False, f"Unexpected error: {str(e)}")


class HybridCryptoApp(QMainWindow):
    """Main application window."""

    def __init__(self):
        """Initialize the main window, UI, and default configuration."""
        super().__init__()
        self.setWindowTitle("Hybrid Encryption System (RSA + SM4)")
        self.resize(900, 700)
        self.setMinimumSize(750, 550)

        self.config: Dict[str, str] = {}
        self.path_inputs: Dict[str, QLineEdit] = {}
        self.worker: WorkerThread | None = None

        self._apply_stylesheet()
        self._setup_ui()
        self._load_default_config()

    def _apply_stylesheet(self) -> None:
        """Apply modern high-contrast dark theme."""
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #21252B; color: #F8F8F2; font-size: 13px; }
            QLabel { color: #E5E9F0; font-weight: 500; }
            QGroupBox { font-weight: bold; color: #E5C07B; border: 1px solid #3E4451; border-radius: 6px; margin-top: 12px; padding-top: 18px; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
            QPushButton { background-color: #3E4451; color: #F8F8F2; border: 1px solid #5C6370; padding: 8px 16px; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #4B5263; border: 1px solid #7A828E; }
            QPushButton:pressed { background-color: #2C313A; }
            QPushButton:disabled { background-color: #2C313A; color: #5C6370; border: 1px solid #3E4451; }
            QPushButton#actionBtn { background-color: #4D78CC; border: none; color: #FFFFFF; font-size: 14px; padding: 10px 20px; }
            QPushButton#actionBtn:hover { background-color: #618EEA; }
            QPushButton#actionBtn:disabled { background-color: #2D4A7A; color: #7A828E; }
            QLineEdit { background-color: #282C34; color: #F8F8F2; border: 1px solid #3E4451; padding: 6px 8px; border-radius: 4px; selection-background-color: #4D78CC; }
            QLineEdit:focus { border: 1px solid #61AFEF; }
            QPlainTextEdit { background-color: #181A1F; color: #ABB2BF; border: 1px solid #3E4451; border-radius: 4px; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; }
            QToolTip { background-color: #3E4451; color: #F8F8F2; border: 1px solid #5C6370; }
        """)

    def _setup_ui(self) -> None:
        """Initialize all UI components and layouts."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        config_layout = QHBoxLayout()
        self.btn_load = QPushButton("Load settings.json")
        self.btn_save = QPushButton("Save settings.json")
        self.btn_load.clicked.connect(self._load_config_dialog)
        self.btn_save.clicked.connect(self._save_config_dialog)
        config_layout.addWidget(self.btn_load)
        config_layout.addWidget(self.btn_save)
        config_layout.addStretch()
        main_layout.addLayout(config_layout)

        paths_group = QGroupBox("File Paths Configuration")
        form_layout = QFormLayout()
        
        path_keys = [
            ("initial_file", "Initial Plaintext File:"),
            ("encrypted_file", "Encrypted File:"),
            ("decrypted_file", "Decrypted File:"),
            ("symmetric_key", "Encrypted Symmetric Key:"),
            ("public_key", "RSA Public Key:"),
            ("secret_key", "RSA Private Key:")
        ]

        for key, label in path_keys:
            layout = QHBoxLayout()
            line_edit = QLineEdit()
            self.path_inputs[key] = line_edit
            
            browse_btn = QPushButton("Browse...")
            browse_btn.clicked.connect(lambda checked, k=key: self._browse_file(k))
            
            layout.addWidget(line_edit)
            layout.addWidget(browse_btn)
            form_layout.addRow(label, layout)

        paths_group.setLayout(form_layout)
        main_layout.addWidget(paths_group)

        action_layout = QHBoxLayout()
        self.btn_gen = QPushButton("1. Generate Keys")
        self.btn_enc = QPushButton("2. Encrypt Data")
        self.btn_dec = QPushButton("3. Decrypt Data")
        
        for btn in (self.btn_gen, self.btn_enc, self.btn_dec):
            btn.setObjectName("actionBtn")
            
        self.btn_gen.clicked.connect(lambda: self._run_task(script.run_generation))
        self.btn_enc.clicked.connect(lambda: self._run_task(script.run_encryption))
        self.btn_dec.clicked.connect(lambda: self._run_task(script.run_decryption))

        action_layout.addWidget(self.btn_gen)
        action_layout.addWidget(self.btn_enc)
        action_layout.addWidget(self.btn_dec)
        main_layout.addLayout(action_layout)

        console_group = QGroupBox("Execution Log")
        console_layout = QVBoxLayout()
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)
        console_group.setLayout(console_layout)
        main_layout.addWidget(console_group)

    def _browse_file(self, key: str) -> None:
        """
        Open file dialog and update path variable.

        Args:
            key (str): The configuration key representing the file type.
        """
        current_path = self.path_inputs[key].text()
        start_dir = os.path.dirname(current_path) if current_path else os.path.expanduser("~")

        match key:
            case "initial_file":
                path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt", start_dir, "All Files (*)")
            case _:
                path, _ = QFileDialog.getSaveFileName(self, "Select Save Location", start_dir, "All Files (*)")
            
        if path:
            self.path_inputs[key].setText(path)

    def _load_default_config(self) -> None:
        """Load settings.json on startup if it exists."""
        if os.path.exists("settings.json"):
            self._load_config("settings.json")

    def _load_config_dialog(self) -> None:
        """Open dialog to load configuration file."""
        path, _ = QFileDialog.getOpenFileName(self, "Load Configuration", "", "JSON Files (*.json)")
        if path:
            self._load_config(path)

    def _load_config(self, path: str) -> None:
        """
        Read JSON and update UI.

        Args:
            path (str): Path to the JSON file.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.config = json.load(f)
            
            for key, line_edit in self.path_inputs.items():
                if key in self.config:
                    line_edit.setText(self.config[key])
            
            self._append_log(f"[INFO] Configuration loaded from {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load config:\n{e}")

    def _save_config_dialog(self) -> None:
        """Open dialog to save configuration file."""
        path, _ = QFileDialog.getSaveFileName(self, "Save Configuration", "settings.json", "JSON Files (*.json)")
        if path:
            self._save_config(path)

    def _save_config(self, path: str) -> None:
        """
        Read UI and save to JSON.

        Args:
            path (str): Destination path for the JSON file.
        """
        try:
            self.config = {key: line_edit.text() for key, line_edit in self.path_inputs.items()}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4)
            self._append_log(f"[INFO] Configuration saved to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save config:\n{e}")

    def _append_log(self, message: str) -> None:
        """
        Thread-safe UI update for logging with color coding.

        Args:
            message (str): The log message to display.
        """
        prefix = message.split("]")[0] + "]" if "]" in message else ""
        
        match prefix:
            case "[SUCCESS]": color = "#98C379"
            case "[ERROR]" | "[CRITICAL]": color = "#E06C75"
            case "[WARNING]": color = "#E5C07B"
            case "[INFO]": color = "#61AFEF"
            case _: color = "#ABB2BF"
            
        safe_message = html.escape(message)
        html_message = f'<span style="color:{color};">{safe_message}</span>'
        
        self.console.appendHtml(html_message)
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def _set_buttons_enabled(self, enabled: bool) -> None:
        """
        Enable or disable all action buttons.

        Args:
            enabled (bool): True to enable, False to disable.
        """
        self.btn_gen.setEnabled(enabled)
        self.btn_enc.setEnabled(enabled)
        self.btn_dec.setEnabled(enabled)
        self.btn_load.setEnabled(enabled)
        self.btn_save.setEnabled(enabled)

    def _run_task(self, task_func: Callable) -> None:
        """
        Run cryptographic task in a background thread.

        Args:
            task_func (Callable): The orchestration function to execute.
        """
        self.config = {key: line_edit.text() for key, line_edit in self.path_inputs.items()}
        self._append_log("-" * 60)
        
        self._set_buttons_enabled(False)
        
        self.worker = WorkerThread(task_func, self.config)
        self.worker.log_signal.connect(self._append_log)
        self.worker.finished_signal.connect(self._on_task_finished)
        self.worker.start()

    def _on_task_finished(self, success: bool, message: str) -> None:
        """
        Handle task completion.

        Args:
            success (bool): True if the task succeeded, False otherwise.
            message (str): Completion or error message.
        """
        self._set_buttons_enabled(True)
        if success:
            self._append_log(f"[SUCCESS] {message}")
        else:
            self._append_log(f"[ERROR] {message}")
            QMessageBox.warning(self, "Operation Failed", message)


def main() -> None:
    """Application entry point with Windows plugin fix."""
    if sys.platform == 'win32':
        import PyQt5
        base_dir = os.path.dirname(PyQt5.__file__)
        paths_to_try = [
            os.path.join(base_dir, 'Qt5', 'plugins', 'platforms'),
            os.path.join(base_dir, 'Qt', 'plugins', 'platforms')
        ]
        for plugin_path in paths_to_try:
            if os.path.exists(plugin_path):
                os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = plugin_path
                break

    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = HybridCryptoApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()