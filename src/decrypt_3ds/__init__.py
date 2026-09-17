from argparse import ArgumentParser, ArgumentTypeError


def _rom_file(value: str) -> str:
    if not value.lower().endswith((".3ds", ".cia")):
        raise ArgumentTypeError(f"expected a .3ds or .cia file, got {value!r}")
    return value


def main() -> int:
    parser = ArgumentParser(
        prog="decrypt-3ds",
        description="Decrypt Nintendo 3DS .3ds and .cia ROM files.",
    )
    parser.add_argument("rom", type=_rom_file, help=".3ds or .cia file to decrypt")
    args = parser.parse_args()

    if args.rom.lower().endswith(".3ds"):
        from .decrypt_3ds import decrypt

        decrypt(args.rom)
    elif args.rom.lower().endswith(".cia"):
        from .decrypt_cia import decrypt_cia

        decrypt_cia(args.rom)

    return 0


if __name__ == "__main__":
    # raise SystemExit(main())
    main()
