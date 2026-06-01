from typing import Final

HMAC_DIGEST_HEX_LENGTH: Final[int] = 64

GUI_WINDOW_TITLE: Final[str] = "Lab 4 – HMAC"
GUI_MESSAGE_LABEL: Final[str] = "Message:"
GUI_KEY_LABEL: Final[str] = "Secret key:"
GUI_GENERATE_BTN: Final[str] = "Compute HMAC"
GUI_VERIFY_BTN: Final[str] = "Verify HMAC"
GUI_TAMPER_BTN: Final[str] = "Tamper message"
GUI_STATUS_WAITING: Final[str] = "Status: waiting..."
GUI_STATUS_GENERATED: Final[str] = "HMAC generated. Ready to verify."
GUI_STATUS_AUTH_OK: Final[str] = "Authenticity confirmed (HMAC matches)"
GUI_STATUS_AUTH_FAIL: Final[str] = "HMAC mismatch! Message or key modified."
GUI_STATUS_TAMPERED: Final[str] = "Message tampered! Click 'Verify HMAC'."
GUI_ERROR_EMPTY: Final[str] = "Message and key cannot be empty."
GUI_ERROR_NO_HMAC: Final[str] = "Generate HMAC first."
GUI_ERROR_EMPTY_TAMPER: Final[str] = "Message is empty, nothing to tamper."