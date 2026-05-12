import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

SM4_KEY_SIZE_BYTES = 16
SM4_BLOCK_SIZE_BITS = 128
RSA_KEY_SIZE_BITS = 2048


class CryptoAppError(Exception):
    """Base exception for all application-specific errors."""
    pass


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


def generate_symmetric_key() -> bytes:
    """
    Generate a cryptographically secure symmetric key for SM4.

    Returns:
        bytes: A random byte sequence of SM4_KEY_SIZE_BYTES.
    """
    return os.urandom(SM4_KEY_SIZE_BYTES)


def generate_rsa_private_key(key_size: int = RSA_KEY_SIZE_BITS) -> rsa.RSAPrivateKey:
    """
    Generate an RSA private key.

    Args:
        key_size (int): The size of the key in bits.

    Returns:
        rsa.RSAPrivateKey: The generated private key object.

    Raises:
        CryptoAppError: If key generation fails.
    """
    try:
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    except Exception as e:
        raise CryptoAppError(f"RSA key generation failed: {e}")


def derive_rsa_public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    """
    Derive the RSA public key from a private key.

    Args:
        private_key (rsa.RSAPrivateKey): The RSA private key object.

    Returns:
        rsa.RSAPublicKey: The corresponding public key object.
    """
    return private_key.public_key()


def serialize_rsa_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Serialize an RSA private key to PEM format.

    Args:
        private_key (rsa.RSAPrivateKey): The RSA private key object.

    Returns:
        bytes: PEM-encoded private key.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_rsa_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Serialize an RSA public key to PEM format.

    Args:
        public_key (rsa.RSAPublicKey): The RSA public key object.

    Returns:
        bytes: PEM-encoded public key.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_rsa_private_key(pem_data: bytes) -> rsa.RSAPrivateKey:
    """
    Deserialize an RSA private key from PEM format.

    Args:
        pem_data (bytes): The PEM-encoded private key data.

    Returns:
        rsa.RSAPrivateKey: The deserialized private key object.

    Raises:
        CryptoAppError: If the PEM data is invalid or corrupted.
    """
    try:
        return serialization.load_pem_private_key(pem_data, password=None)
    except Exception as e:
        raise CryptoAppError(f"Invalid RSA private key format: {e}")


def encrypt_symmetric_key(symmetric_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt a symmetric key using an RSA public key with OAEP padding.

    Args:
        symmetric_key (bytes): The raw symmetric key.
        public_key (rsa.RSAPublicKey): The RSA public key object.

    Returns:
        bytes: The encrypted symmetric key.

    Raises:
        CryptoAppError: If encryption fails.
    """
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
    """
    Decrypt a symmetric key using an RSA private key with OAEP padding.

    Args:
        encrypted_sym_key (bytes): The encrypted symmetric key.
        private_key (rsa.RSAPrivateKey): The RSA private key object.

    Returns:
        bytes: The decrypted raw symmetric key.

    Raises:
        CryptoAppError: If decryption fails (wrong key or corrupted data).
    """
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


def encrypt_data_sm4(plaintext: bytes, symmetric_key: bytes) -> bytes:
    """
    Encrypt data using SM4-CBC with PKCS7 padding.

    Args:
        plaintext (bytes): The raw data to encrypt.
        symmetric_key (bytes): The 128-bit SM4 symmetric key.

    Returns:
        bytes: The 16-byte IV followed by the ciphertext.

    Raises:
        CryptoAppError: If encryption fails.
    """
    try:
        iv = os.urandom(SM4_KEY_SIZE_BYTES)
        padder = sym_padding.PKCS7(SM4_BLOCK_SIZE_BITS).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + ciphertext
    except Exception as e:
        raise CryptoAppError(f"SM4 encryption failed: {e}")


def decrypt_data_sm4(encrypted_data: bytes, symmetric_key: bytes) -> bytes:
    """
    Decrypt data using SM4-CBC with PKCS7 padding.

    Args:
        encrypted_data (bytes): The 16-byte IV followed by the ciphertext.
        symmetric_key (bytes): The 128-bit SM4 symmetric key.

    Returns:
        bytes: The decrypted plaintext data.

    Raises:
        CryptoAppError: If decryption fails or data is too short/corrupted.
    """
    try:
        if len(encrypted_data) < SM4_KEY_SIZE_BYTES:
            raise CryptoAppError("Encrypted data is too short to contain IV.")
            
        iv = encrypted_data[:SM4_KEY_SIZE_BYTES]
        ciphertext = encrypted_data[SM4_KEY_SIZE_BYTES:]

        cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(SM4_BLOCK_SIZE_BITS).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()
    except CryptoAppError:
        raise
    except Exception as e:
        raise CryptoAppError(f"SM4 decryption failed: {e}")