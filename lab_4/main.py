import argparse
import sys
from typing import NoReturn

from hmac_utils import compute_hmac, verify_hmac
from collision import find_collision
from settings_loader import load_settings

try:
    from app import run_gui
    GUI_AVAILABLE = True
except ImportError as e:
    GUI_AVAILABLE = False
    _gui_import_error = e


def main() -> NoReturn:
    """Parse arguments and dispatch to appropriate mode."""
    settings = load_settings()
    collision_cfg = settings['collision']
    default_bits = collision_cfg['bits']
    default_attempts = collision_cfg['max_attempts']

    parser = argparse.ArgumentParser(
        description="Lab 4 – Hash functions and HMAC"
    )
    parser.add_argument(
        '--mode',
        choices=['gui', 'hmac', 'verify', 'collision'],
        default='gui',
        help="Operation mode"
    )
    parser.add_argument('--message', type=str, help="Message for HMAC")
    parser.add_argument('--key', type=str, help="Secret key")
    parser.add_argument('--hmac', type=str, help="Expected HMAC (hex)")
    parser.add_argument(
        '--bits',
        type=int,
        default=default_bits,
        help="Truncation bits for collision (1..32)"
    )
    parser.add_argument(
        '--attempts',
        type=int,
        default=default_attempts,
        help="Maximum collision search attempts"
    )

    args = parser.parse_args()

    match args.mode:
        case 'gui':
            if not GUI_AVAILABLE:
                print("Error: PyQt5 is required for GUI mode.", file=sys.stderr)
                print(f"Import error: {_gui_import_error}", file=sys.stderr)
                sys.exit(1)
            try:
                run_gui()
            except Exception as e:
                print(f"GUI runtime error: {e}", file=sys.stderr)
                sys.exit(1)

        case 'hmac':
            try:
                if not args.message or not args.key:
                    raise ValueError("--message and --key are required for hmac mode.")
                result = compute_hmac(args.message, args.key)
                print(f"HMAC-SHA256: {result}")
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        case 'verify':
            try:
                if not args.message or not args.key or not args.hmac:
                    raise ValueError(
                        "--message, --key and --hmac are required for verify mode."
                    )
                valid = verify_hmac(args.message, args.key, args.hmac)
                match valid:
                    case True:
                        print("Result: Matches")
                    case False:
                        print("Result: Does not match")
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        case 'collision':
            try:
                if args.bits < 1 or args.bits > 32:
                    raise ValueError("Bits must be between 1 and 32.")
                print(f"Searching collision for {args.bits} bits "
                      f"(max {args.attempts} attempts)...")
                result = find_collision(bits=args.bits, max_attempts=args.attempts)
                match result:
                    case None:
                        print("Collision not found within given limits.")
                    case (m1, m2, h):
                        print("Collision found!")
                        print(f"Message 1 (hex): {m1.hex()}")
                        print(f"Message 2 (hex): {m2.hex()}")
                        print(f"Truncated hash: {hex(h)}")
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        case _:
            print(f"Unknown mode: {args.mode}", file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()