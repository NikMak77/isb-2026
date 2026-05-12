from typing import Callable, Dict, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
import utils


def _load_keys(config: Dict[str, str], log: Callable[[str], None]) -> Tuple[rsa.RSAPrivateKey, bytes]:
    """
    Load and decrypt the symmetric key using the RSA private key.

    Args:
        config (Dict[str, str]): Configuration dictionary with file paths.
        log (Callable[[str], None]): Logging callback function.

    Returns:
        Tuple[rsa.RSAPrivateKey, bytes]: The RSA private key and the decrypted symmetric key.
    """
    log("[INFO] Reading RSA private key and encrypted symmetric key...")
    priv_key_pem = utils.read_file(config["secret_key"])
    enc_sym_key_data = utils.read_file(config["symmetric_key"])
    
    log("[INFO] Deserializing RSA private key...")
    private_key = utils.deserialize_rsa_private_key(priv_key_pem)
    
    log("[INFO] Decrypting symmetric key...")
    symmetric_key = utils.decrypt_symmetric_key(enc_sym_key_data, private_key)
    
    return private_key, symmetric_key


def run_generation(config: Dict[str, str], log: Callable[[str], None] = print) -> None:
    """
    Script 1: Hybrid key generation.

    Args:
        config (Dict[str, str]): Configuration dictionary with file paths.
        log (Callable[[str], None]): Logging callback function.
    """
    log("[INFO] Script 1: Starting hybrid key generation...")
    
    log("[INFO] Step 1.1: Generating 128-bit symmetric key (SM4)...")
    sym_key = utils.generate_symmetric_key()
    
    log("[INFO] Step 1.2: Generating 2048-bit RSA private key...")
    priv_key = utils.generate_rsa_private_key()
    
    log("[INFO] Step 1.3: Deriving RSA public key...")
    pub_key = utils.derive_rsa_public_key(priv_key)
    
    log("[INFO] Step 1.4: Serializing RSA keys to PEM format...")
    priv_key_pem = utils.serialize_rsa_private_key(priv_key)
    pub_key_pem = utils.serialize_rsa_public_key(pub_key)
    
    log("[INFO] Step 1.5: Encrypting symmetric key with RSA public key...")
    enc_sym_key = utils.encrypt_symmetric_key(sym_key, pub_key)
    
    log("[INFO] Step 1.6: Saving all artifacts to disk...")
    utils.save_to_file(priv_key_pem, config["secret_key"])
    utils.save_to_file(pub_key_pem, config["public_key"])
    utils.save_to_file(enc_sym_key, config["symmetric_key"])
    
    log("[SUCCESS] Script 1: Key generation completed successfully.")


def run_encryption(config: Dict[str, str], log: Callable[[str], None] = print) -> None:
    """
    Script 2: Hybrid data encryption.

    Args:
        config (Dict[str, str]): Configuration dictionary with file paths.
        log (Callable[[str], None]): Logging callback function.
    """
    log("[INFO] Script 2: Starting data encryption...")
    
    _, symmetric_key = _load_keys(config, log)
    
    log("[INFO] Step 2.1: Reading plaintext file...")
    plaintext = utils.read_file(config["initial_file"])
    
    log("[INFO] Step 2.2: Encrypting data with SM4-CBC...")
    encrypted_data = utils.encrypt_data_sm4(plaintext, symmetric_key)
    
    log("[INFO] Step 2.3: Saving encrypted data to disk...")
    utils.save_to_file(encrypted_data, config["encrypted_file"])
    
    log("[SUCCESS] Script 2: Data encryption completed successfully.")


def run_decryption(config: Dict[str, str], log: Callable[[str], None] = print) -> None:
    """
    Script 3: Hybrid data decryption.

    Args:
        config (Dict[str, str]): Configuration dictionary with file paths.
        log (Callable[[str], None]): Logging callback function.
    """
    log("[INFO] Script 3: Starting data decryption...")
    
    _, symmetric_key = _load_keys(config, log)
    
    log("[INFO] Step 3.1: Reading encrypted data file...")
    encrypted_data = utils.read_file(config["encrypted_file"])
    
    log("[INFO] Step 3.2: Decrypting data with SM4-CBC and removing padding...")
    decrypted_data = utils.decrypt_data_sm4(encrypted_data, symmetric_key)
    
    log("[INFO] Step 3.3: Saving decrypted data to disk...")
    utils.save_to_file(decrypted_data, config["decrypted_file"])
    
    log("[SUCCESS] Script 3: Data decryption completed successfully.")