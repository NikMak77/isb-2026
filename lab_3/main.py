import argparse
import sys
import file_io
import utils
import key_generate
import data_encryption
import data_decryption

DEFAULT_CONFIG_PATH = "settings.json"


def main() -> None:
    """Initialize the CLI parser, load config, and route commands."""
    parser = argparse.ArgumentParser(description="Hybrid Encryption System (RSA + SM4)")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true', help='Key generation mode')
    group.add_argument('-enc', '--encryption', action='store_true', help='Data encryption mode')
    group.add_argument('-dec', '--decryption', action='store_true', help='Data decryption mode')
    
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG_PATH, help='Path to JSON configuration file')

    args = parser.parse_args()
    
    print(f"[INFO] Loading configuration from {args.config}...")
    
    try:
        config = file_io.load_json_config(args.config)
    except utils.CryptoAppError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    command = "gen" if args.generation else "enc" if args.encryption else "dec" if args.decryption else "none"

    try:
        match command:
            case "gen":
                key_generate.run_generation(config)
            case "enc":
                data_encryption.run_encryption(config)
            case "dec":
                data_decryption.run_decryption(config)
            case _:
                print("[ERROR] No valid command specified.")
                sys.exit(1)
    except utils.CryptoAppError as e:
        print(f"\n[ERROR] Operation failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[CRITICAL] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()