import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from exceptions import CryptoAppError
import file_io


@dataclass
class CryptoConfig:
    """Dataclass to hold cryptographic constants."""
    sm4_key_size_bytes: int
    sm4_block_size_bits: int
    rsa_key_size_bits: int
    rsa_public_exponent: int


def generate_symmetric_key(cfg: CryptoConfig) -> bytes:
    """Generate a cryptographically secure symmetric key for SM4."""
    return os.urandom(cfg.sm4_key_size_bytes)


def generate_rsa_private_key(cfg: CryptoConfig) -> rsa.RSAPrivateKey:
    """Generate an RSA private key."""
    try:
        return rsa.generate_private_key(
            public_exponent=cfg.rsa_public_exponent, 
            key_size=cfg.rsa_key_size_bits
        )
    except Exception as e:
        raise CryptoAppError(f"RSA key generation failed: {e}")


def derive_rsa_public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    """Derive the RSA public key from a private key."""
    return private_key.public_key()


def serialize_rsa_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_rsa_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize an RSA public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_rsa_private_key(pem_data: bytes) -> rsa.RSAPrivateKey:
    """Deserialize an RSA private key from PEM format."""
    try:
        return serialization.load_pem_private_key(pem_data, password=None)
    except Exception as e:
        raise CryptoAppError(f"Invalid RSA private key format: {e}")


def encrypt_symmetric_key(symmetric_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt a symmetric key using an RSA public key with OAEP padding."""
    try:
        return public_key.encrypt(
            symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise CryptoAppError(f"Symmetric key encryption failed: {e}")


def decrypt_symmetric_key(encrypted_sym_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt a symmetric key using an RSA private key with OAEP padding."""
    try:
        return private_key.decrypt(
            encrypted_sym_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise CryptoAppError(f"Symmetric key decryption failed: {e}")


def encrypt_data_sm4(plaintext: bytes, symmetric_key: bytes, cfg: CryptoConfig) -> bytes:
    """Encrypt data using SM4-CBC with PKCS7 padding."""
    try:
        iv = os.urandom(cfg.sm4_key_size_bytes)
        padder = sym_padding.PKCS7(cfg.sm4_block_size_bits).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + ciphertext
    except Exception as e:
        raise CryptoAppError(f"SM4 encryption failed: {e}")


def decrypt_data_sm4(encrypted_data: bytes, symmetric_key: bytes, cfg: CryptoConfig) -> bytes:
    """Decrypt data using SM4-CBC with PKCS7 padding."""
    try:
        if len(encrypted_data) < cfg.sm4_key_size_bytes:
            raise CryptoAppError("Encrypted data is too short to contain IV.")
            
        iv = encrypted_data[:cfg.sm4_key_size_bytes]
        ciphertext = encrypted_data[cfg.sm4_key_size_bytes:]

        cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(cfg.sm4_block_size_bits).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()
    except CryptoAppError:
        raise
    except Exception as e:
        raise CryptoAppError(f"SM4 decryption failed: {e}")


def get_decrypted_symmetric_key(paths: dict) -> bytes:
    """Load and decrypt the symmetric key using the RSA private key."""
    priv_key_pem = file_io.read_file(paths["secret_key"])
    enc_sym_key_data = file_io.read_file(paths["symmetric_key"])
    private_key = deserialize_rsa_private_key(priv_key_pem)
    return decrypt_symmetric_key(enc_sym_key_data, private_key)