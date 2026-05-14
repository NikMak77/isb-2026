from typing import Callable, Dict
import utils
import file_io


def run_generation(config: Dict, log: Callable[[str], None] = print) -> None:
    """Hybrid key generation."""
    paths = config["paths"]
    cfg = utils.CryptoConfig(**config["constants"])

    log("[INFO] Script 1: Starting hybrid key generation...")
    
    log("[INFO] Step 1.1: Generating symmetric key (SM4)...")
    sym_key = utils.generate_symmetric_key(cfg)
    
    log("[INFO] Step 1.2: Generating RSA private key...")
    priv_key = utils.generate_rsa_private_key(cfg)
    
    log("[INFO] Step 1.3: Deriving RSA public key...")
    pub_key = utils.derive_rsa_public_key(priv_key)
    
    log("[INFO] Step 1.4: Serializing RSA keys to PEM format...")
    priv_key_pem = utils.serialize_rsa_private_key(priv_key)
    pub_key_pem = utils.serialize_rsa_public_key(pub_key)
    
    log("[INFO] Step 1.5: Encrypting symmetric key with RSA public key...")
    enc_sym_key = utils.encrypt_symmetric_key(sym_key, pub_key)
    
    log("[INFO] Step 1.6: Saving all artifacts to disk...")
    file_io.save_to_file(priv_key_pem, paths["secret_key"])
    file_io.save_to_file(pub_key_pem, paths["public_key"])
    file_io.save_to_file(enc_sym_key, paths["symmetric_key"])
    
    log("[SUCCESS] Script 1: Key generation completed successfully.")