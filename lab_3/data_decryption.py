from typing import Callable, Dict
import utils
import file_io


def run_decryption(config: Dict, log: Callable[[str], None] = print) -> None:
    """Hybrid data decryption."""
    paths = config["paths"]
    cfg = utils.CryptoConfig(**config["constants"])

    log("[INFO] Script 3: Starting data decryption...")
    
    log("[INFO] Step 3.1: Loading and decrypting symmetric key...")
    symmetric_key = utils.get_decrypted_symmetric_key(paths)
    
    log("[INFO] Step 3.2: Reading encrypted data file...")
    encrypted_data = file_io.read_file(paths["encrypted_file"])
    
    log("[INFO] Step 3.3: Decrypting data with SM4-CBC...")
    decrypted_data = utils.decrypt_data_sm4(encrypted_data, symmetric_key, cfg)
    
    log("[INFO] Step 3.4: Saving decrypted data to disk...")
    file_io.save_to_file(decrypted_data, paths["decrypted_file"])
    
    log("[SUCCESS] Script 3: Data decryption completed successfully.")