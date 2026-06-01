import argparse
import sys
from typing import NoReturn

from hmac_utils import compute_hmac, verify_hmac

try:
    from app import run_gui
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


def main() -> NoReturn:
    parser = argparse.ArgumentParser(description="Lab 4 – HMAC")
    parser.add_argument(
        '--mode',
        choices=['gui', 'hmac', 'verify'],
        default='gui',
        help="Operation mode"
    )
    parser.add_argument('--message', type=str, help="Message for HMAC")
    parser.add_argument('--key', type=str, help="Secret key")
    parser.add_argument('--hmac', type=str, help="Expected HMAC (hex)")

    args = parser.parse_args()

    if args.mode == 'gui':
        if not GUI_AVAILABLE:
            print("Error: PyQt5 is required for GUI mode.", file=sys.stderr)
            sys.exit(1)
        try:
            run_gui()
        except Exception as e:
            print(f"GUI runtime error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.mode == 'hmac':
        try:
            if not args.message or not args.key:
                raise ValueError("--message and --key are required for hmac mode.")
            result = compute_hmac(args.message, args.key)
            print(f"HMAC-SHA256: {result}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.mode == 'verify':
        try:
            if not args.message or not args.key or not args.hmac:
                raise ValueError("--message, --key and --hmac are required for verify mode.")
            valid = verify_hmac(args.message, args.key, args.hmac)
            print("Result: Matches" if valid else "Result: Does not match")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()