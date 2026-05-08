import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def read_file(file_path: str) -> bytes:
    """
    Read binary data from a file.

    Note: Loads the entire file into memory. For very large files, 
    a streaming approach should be implemented.

    Args:
        file_path (str): The path to the file to read.

    Returns:
        bytes: The content of the file.
    """
    with open(file_path, "rb") as f:
        return f.read()


def deserialize_rsa_private_key(pem_data: bytes) -> rsa.RSAPrivateKey:
    """
    Deserialize an RSA private key from PEM format.

    Args:
        pem_data (bytes): The PEM-encoded private key.

    Returns:
        rsa.RSAPrivateKey: The RSA private key object.
    """
    return serialization.load_pem_private_key(
        pem_data,
        password=None
    )


def decrypt_symmetric_key(encrypted_sym_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypt a symmetric key using an RSA private key with OAEP padding.

    Args:
        encrypted_sym_key (bytes): The encrypted symmetric key.
        private_key (rsa.RSAPrivateKey): The RSA private key object.

    Returns:
        bytes: The decrypted raw symmetric key.
    """
    return private_key.decrypt(
        encrypted_sym_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def encrypt_data_sm4(plaintext: bytes, symmetric_key: bytes) -> bytes:
    """
    Encrypt data using the SM4 symmetric algorithm in CBC mode with PKCS7 padding.

    A random 16-byte Initialization Vector (IV) is generated and prepended 
    to the ciphertext.

    Args:
        plaintext (bytes): The data to encrypt.
        symmetric_key (bytes): The 128-bit SM4 symmetric key.

    Returns:
        bytes: The IV followed by the ciphertext.
    """
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext


def save_to_file(data: bytes, file_path: str) -> None:
    """
    Save binary data to a file, creating directories if they don't exist.

    Args:
        data (bytes): The data to save.
        file_path (str): The destination file path.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    
    with open(file_path, "wb") as f:
        f.write(data)


def run_data_encryption_script(
    plaintext_path: str, 
    priv_key_path: str, 
    enc_sym_key_path: str, 
    output_path: str
) -> None:
    """
    Orchestrate the full data encryption script.

    Args:
        plaintext_path (str): Path to the plaintext file to encrypt.
        priv_key_path (str): Path to the RSA private key.
        enc_sym_key_path (str): Path to the encrypted symmetric key.
        output_path (str): Path to save the encrypted data.
    """
    print("Step 2.1.1: Reading encrypted symmetric key and RSA private key...")
    enc_sym_key_data = read_file(enc_sym_key_path)
    priv_key_pem = read_file(priv_key_path)

    print("Step 2.1.2: Deserializing RSA private key...")
    private_key = deserialize_rsa_private_key(priv_key_pem)

    print("Step 2.1.3: Decrypting symmetric key...")
    symmetric_key = decrypt_symmetric_key(enc_sym_key_data, private_key)

    print("Step 2.2.1: Reading plaintext file...")
    plaintext = read_file(plaintext_path)

    print("Step 2.2.2: Encrypting data with SM4...")
    encrypted_data = encrypt_data_sm4(plaintext, symmetric_key)

    print("Step 2.2.3: Saving encrypted data to disk...")
    save_to_file(encrypted_data, output_path)

    print(f"Done!\nEncrypted data saved to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script 2: Hybrid data encryption")
    parser.add_argument("--input", required=True, help="Path to the plaintext file to encrypt")
    parser.add_argument("--priv-key", required=True, help="Path to the RSA private key")
    parser.add_argument("--enc-sym-key", required=True, help="Path to the encrypted symmetric key")
    parser.add_argument("--output", required=True, help="Path to save the encrypted file")

    args = parser.parse_args()

    run_data_encryption_script(
        args.input, 
        args.priv_key, 
        args.enc_sym_key, 
        args.output
    )