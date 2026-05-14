from typing import Callable, Dict
import utils
import file_io


def run_encryption(config: Dict, log: Callable[[str], None] = print) -> None:
    """Hybrid data encryption."""
    paths = config["paths"]
    cfg = utils.CryptoConfig(**config["constants"])

    log("[INFO] Script 2: Starting data encryption...")
    
    log("[INFO] Step 2.1: Loading and decrypting symmetric key...")
    symmetric_key = utils.get_decrypted_symmetric_key(paths)
    
    log("[INFO] Step 2.2: Reading plaintext file...")
    plaintext = file_io.read_file(paths["initial_file"])
    
    log("[INFO] Step 2.3: Encrypting data with SM4-CBC...")
    encrypted_data = utils.encrypt_data_sm4(plaintext, symmetric_key, cfg)
    
    log("[INFO] Step 2.4: Saving encrypted data to disk...")
    file_io.save_to_file(encrypted_data, paths["encrypted_file"])
    
    log("[SUCCESS] Script 2: Data encryption completed successfully.")