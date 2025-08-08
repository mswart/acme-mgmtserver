#!/usr/bin/env python3
import argparse
import importlib.metadata
import sys

from .config import Configurator
from .exceptions import NeedToAgreeToTOS
from .manager import ACMEManager


def main():
    parser = argparse.ArgumentParser(add_help=False, description="Register a the ACME server")
    group = parser.add_argument_group(
        "general options",
    )
    group.add_argument(
        "configs",
        type=argparse.FileType("r"),
        nargs="+",
        metavar="CONFIG",
        help="file path to configuration file",
    )
    group.add_argument(
        "--version",
        "-V",
        action="version",
        version="%(prog)s " + importlib.metadata.version("acme-mgmtserver"),
    )
    group.add_argument("--help", "-h", action="help", help="show this help message and exit")

    group = parser.add_argument_group(
        "key management",
        "option around creating/management the RSA private key for commuincation with the ACME server",
    )
    group.add_argument(
        "--gen-key",
        action="store_true",
        default=False,
        help="generate new private key for communication with the ACME server",
    )
    group.add_argument(
        "--private-key-size", default=4096, type=int, help="private key size to create"
    )
    group.add_argument(
        "--override-existing-key",
        default=False,
        action="store_true",
        help="override an existing private key?",
    )

    group = parser.add_argument_group(
        "registration management",
        "option around the account registration at the ACME server (a private key is needed!)",
    )
    group.add_argument(
        "--register", action="store_true", default=False, help="register key at ACME server"
    )
    group.add_argument(
        "--email",
        action="append",
        dest="emails",
        default=[],
        help="email contract info (e.g. for expire mail; multiple possible)",
    )
    group.add_argument(
        "--accept-terms-of-service",
        metavar="URL",
        help="accept the terms of server (ToS) of the ACME server",
    )
    args = parser.parse_args()

    config = Configurator(*args.configs)
    manager = ACMEManager(config, connect=False)

    if args.gen_key:
        print("Generate private key ...", end="")
        sys.stdout.flush()
        manager.create_private_key(force=args.override_existing_key, key_size=args.private_key_size)
        print(" done")
    else:
        print("Load private key ...", end="")
        sys.stdout.flush()
        manager.load_private_key()
        print(" done")

    print("Initialize ACME client ...", end="")
    sys.stdout.flush()
    manager.init_client()
    print(" done")

    if args.register:
        print("Register ...", end="")
        sys.stdout.flush()
        manager.register(emails=args.emails, tos_agreement=args.accept_terms_of_service)
        print(" done")
        if manager.tos_agreement_required():
            print(
                "You need to accept the terms of service at {}".format(
                    manager.tos_agreement_required()
                )
            )
    elif args.accept_terms_of_service:
        print("Accepting ToS at {} ...".format(args.accept_terms_of_service), end="")
        sys.stdout.flush()
        manager.accept_terms_of_service(args.accept_terms_of_service)
        print(" done")
    else:
        print("Refreshing current registration ...", end="")
        sys.stdout.flush()
        try:
            manager.refresh_registration()
        except NeedToAgreeToTOS as e:
            print(" done")
            print("You need to accept the terms of service at {}".format(e.url))
        else:
            print(" done")


if __name__ == "__main__":
    main()
