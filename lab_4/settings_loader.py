import json
import os
from typing import Any, Dict
from constants import (
    DEFAULT_COLLISION_BITS,
    DEFAULT_MAX_ATTEMPTS,
    GUI_DEFAULT_BITS,
    GUI_PROGRESS_UPDATE_INTERVAL,
    COLLISION_LIMIT_GUI
)


def load_settings() -> Dict[str, Any]:
    """
    Load settings from settings.json if it exists.
    Merge with default values defined in constants.

    Returns:
        Dict with 'collision' and 'gui' sections.
    """
    defaults: Dict[str, Any] = {
        "collision": {
            "bits": DEFAULT_COLLISION_BITS,
            "max_attempts": DEFAULT_MAX_ATTEMPTS,
            "limit_gui": COLLISION_LIMIT_GUI
        },
        "gui": {
            "default_bits": GUI_DEFAULT_BITS,
            "progress_update_interval": GUI_PROGRESS_UPDATE_INTERVAL
        }
    }

    settings_path = os.path.join(os.path.dirname(__file__), 'settings.json')
    if not os.path.exists(settings_path):
        return defaults

    try:
        with open(settings_path, 'r', encoding='utf-8') as f:
            user_settings = json.load(f)
    except (json.JSONDecodeError, IOError, PermissionError) as e:
        print(f"Warning: could not read settings.json ({e}). Using defaults.")
        return defaults

    for section in defaults:
        if section in user_settings:
            defaults[section].update(user_settings[section])

    return defaults