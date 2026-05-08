import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_symmetric_key() -> bytes:
    """
    Generate a 128-bit symmetric key for SM4.

    Returns:
        bytes: 16 bytes of cryptographically secure random data.
    """
    return os.urandom(16)


def generate_rsa_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generate an RSA private key.

    Args:
        key_size (int): The size of the RSA key in bits. Default is 2048.

    Returns:
        rsa.RSAPrivateKey: The generated RSA private key object.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def derive_rsa_public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    """
    Derive the RSA public key from a private key.

    Args:
        private_key (rsa.RSAPrivateKey): The RSA private key object.

    Returns:
        rsa.RSAPublicKey: The corresponding RSA public key object.
    """
    return private_key.public_key()


def serialize_rsa_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Serialize an RSA private key to PEM format.

    Args:
        private_key (rsa.RSAPrivateKey): The RSA private key object.

    Returns:
        bytes: The PEM-encoded private key.
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
        bytes: The PEM-encoded public key.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def encrypt_symmetric_key(symmetric_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt a symmetric key using an RSA public key with OAEP padding.

    Args:
        symmetric_key (bytes): The raw symmetric key to encrypt.
        public_key (rsa.RSAPublicKey): The RSA public key object.

    Returns:
        bytes: The encrypted symmetric key.
    """
    return public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


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


def run_full_script(sym_key_path: str, pub_key_path: str, priv_key_path: str) -> None:
    """
    Orchestrate the full key generation scenario for testing purposes.
    
    In the final application, the UI will call the individual functions 
    above based on user selection.

    Args:
        sym_key_path (str): Path to save the encrypted symmetric key.
        pub_key_path (str): Path to save the RSA public key.
        priv_key_path (str): Path to save the RSA private key.
    """
    print("Step 1.1: Generating symmetric key...")
    sym_key = generate_symmetric_key()

    print("Step 1.2: Generating RSA private key...")
    priv_key = generate_rsa_private_key()

    print("Step 1.3: Deriving RSA public key...")
    pub_key = derive_rsa_public_key(priv_key)

    print("Step 1.4: Serializing RSA private key...")
    priv_key_pem = serialize_rsa_private_key(priv_key)

    print("Step 1.5: Serializing RSA public key...")
    pub_key_pem = serialize_rsa_public_key(pub_key)

    print("Step 1.6: Encrypting symmetric key...")
    enc_sym_key = encrypt_symmetric_key(sym_key, pub_key)

    print("Saving all artifacts to disk...")
    save_to_file(priv_key_pem, priv_key_path)
    save_to_file(pub_key_pem, pub_key_path)
    save_to_file(enc_sym_key, sym_key_path)

    print(f"Done!\n"
          f"Encrypted symmetric key: {sym_key_path}\n"
          f"Public key: {pub_key_path}\n"
          f"Private key: {priv_key_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script 1: Hybrid key generation")
    parser.add_argument("--sym-key", required=True, help="Path to save the encrypted symmetric key")
    parser.add_argument("--pub-key", required=True, help="Path to save the RSA public key")
    parser.add_argument("--priv-key", required=True, help="Path to save the RSA private key")

    args = parser.parse_args()

    run_full_script(args.sym_key, args.pub_key, args.priv_key)