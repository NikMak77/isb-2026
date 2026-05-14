import os
import json
from typing import Dict
from exceptions import CryptoAppError


def read_file(file_path: str) -> bytes:
    """
    Read binary data from a file.

    Args:
        file_path (str): The absolute or relative path to the file.

    Returns:
        bytes: The raw content of the file.

    Raises:
        CryptoAppError: If the file cannot be read or does not exist.
    """
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise CryptoAppError(f"File not found: {file_path}")
    except PermissionError:
        raise CryptoAppError(f"Permission denied: {file_path}")
    except Exception as e:
        raise CryptoAppError(f"Failed to read file {file_path}: {e}")


def save_to_file(data: bytes, file_path: str) -> None:
    """
    Save binary data to a file, creating parent directories if needed.

    Args:
        data (bytes): The raw data to write.
        file_path (str): The destination file path.

    Raises:
        CryptoAppError: If the file cannot be written.
    """
    try:
        dir_name = os.path.dirname(file_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(data)
    except PermissionError:
        raise CryptoAppError(f"Permission denied to write: {file_path}")
    except Exception as e:
        raise CryptoAppError(f"Failed to save file {file_path}: {e}")


def load_json_config(file_path: str) -> Dict:
    """
    Load and parse a JSON configuration file.

    Args:
        file_path (str): Path to the JSON file.

    Returns:
        Dict: Parsed configuration dictionary.

    Raises:
        CryptoAppError: If file reading or JSON parsing fails.
    """
    raw_data = read_file(file_path)
    try:
        return json.loads(raw_data.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise CryptoAppError(f"Invalid JSON format in {file_path}: {e}")


def save_json_config(config: Dict, file_path: str) -> None:
    """
    Save a dictionary to a JSON file.

    Args:
        config (Dict): The configuration dictionary to save.
        file_path (str): Destination file path.

    Raises:
        CryptoAppError: If file writing fails.
    """
    try:
        dir_name = os.path.dirname(file_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        raise CryptoAppError(f"Failed to save config to {file_path}: {e}")