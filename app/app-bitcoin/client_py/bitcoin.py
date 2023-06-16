#!/usr/bin/env python3

import os
import sys
import json
import base64

import argparse
from argparse import ArgumentParser
from typing import Optional

from message_pb2 import RequestGetVersion, RequestGetMasterFingerprint, RequestGetExtendedPubkey, RequestRegisterWallet, RequestGetWalletAddress, RequestSignPsbt, Request, Response
from util import bip32_path_to_list

# TODO: make a proper package for the stream.py module
sys.path.append(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "..", "..", "..", "host"))

import stream  # noqa: E402


class Btc:
    def get_version_prepare_request(self, args: argparse.Namespace):
        get_version = RequestGetVersion()
        message = Request()
        message.get_version.CopyFrom(get_version)
        assert message.WhichOneof("request") == "get_version"
        return message.SerializeToString()

    def get_version_parse_response(self, data: Optional[bytes]):
        response = Response()
        response.ParseFromString(data)
        assert response.WhichOneof("response") == "get_version"
        print(f"version: {response.get_version.version}")
        return

    def get_master_fingerprint_prepare_request(self, args: argparse.Namespace):
        get_master_fingerprint = RequestGetMasterFingerprint()
        message = Request()
        message.get_master_fingerprint.CopyFrom(get_master_fingerprint)
        assert message.WhichOneof("request") == "get_master_fingerprint"
        return message.SerializeToString()

    def get_master_fingerprint_parse_response(self, data: Optional[bytes]):
        response = Response()
        response.ParseFromString(data)
        assert response.WhichOneof("response") == "get_master_fingerprint"
        fpr_hex = '{:08x}'.format(response.get_master_fingerprint.fingerprint)
        print(f"master fpr: {fpr_hex}")
        return

    def get_extended_pubkey_prepare_request(self, args: argparse.Namespace):
        if args.path is None:
            print("Missing --path argument")
            sys.exit()

        get_extended_pubkey = RequestGetExtendedPubkey()
        get_extended_pubkey.display = args.display
        get_extended_pubkey.bip32_path.extend(bip32_path_to_list(args.path))
        message = Request()
        message.get_extended_pubkey.CopyFrom(get_extended_pubkey)

        assert message.WhichOneof("request") == "get_extended_pubkey"
        return message.SerializeToString()

    def get_extended_pubkey_parse_response(self, data: Optional[bytes]):
        response = Response()
        response.ParseFromString(data)
        assert response.WhichOneof("response") == "get_extended_pubkey"
        print(f"pubkey: {response.get_extended_pubkey.pubkey}")
        return

    def register_wallet_prepare_request(self, args: argparse.Namespace):
        if args.name == "":
            print("Missing or empty --name argument")
            sys.exit()

        if args.descriptor_template is None:
            print("Missing --descriptor_template argument")
            sys.exit()

        if args.keys_info is None:
            print("Missing --keys_info")
            sys.exit()

        try:
            keys_info = json.loads(args.keys_info)
        except json.decoder.JSONDecodeError:
            print("key_info is not valid JSON")
            sys.exit()

        register_wallet = RequestRegisterWallet()
        register_wallet.name = args.name
        register_wallet.descriptor_template = args.descriptor_template
        register_wallet.keys_info.extend(keys_info)
        message = Request()
        message.register_wallet.CopyFrom(register_wallet)

        assert message.WhichOneof("request") == "register_wallet"
        return message.SerializeToString()

    def register_wallet_parse_response(self, data: Optional[bytes]):
        response = Response()
        response.ParseFromString(data)
        assert response.WhichOneof("response") == "register_wallet"
        print(f"id: {response.register_wallet.wallet_id}")
        print(f"hmac: {response.register_wallet.wallet_hmac}")
        return

    def get_wallet_address_prepare_request(self, args: argparse.Namespace):
        if args.descriptor_template is None:
            print("Missing --descriptor_template argument")
            sys.exit()

        if args.keys_info is None:
            print("Missing --keys_info")
            sys.exit()

        try:
            keys_info = json.loads(args.keys_info)
        except json.decoder.JSONDecodeError:
            print("key_info is not valid JSON")
            sys.exit()

        get_wallet_address = RequestGetWalletAddress()
        get_wallet_address.name = args.name
        get_wallet_address.descriptor_template = args.descriptor_template
        get_wallet_address.keys_info.extend(keys_info)
        get_wallet_address.change = args.change
        get_wallet_address.address_index = args.address_index
        message = Request()
        message.get_wallet_address.CopyFrom(get_wallet_address)

        assert message.WhichOneof("request") == "get_wallet_address"
        return message.SerializeToString()

    def get_wallet_address_parse_response(self, data: Optional[bytes]):
        response = Response()
        response.ParseFromString(data)
        assert response.WhichOneof("response") == "get_wallet_address"
        print(f"address: {response.get_wallet_address.address}")
        return

    def sign_psbt_prepare_request(self, args: argparse.Namespace):
        if args.psbt is None:
            print("Missing --psbt argument")
            sys.exit()

        if args.descriptor_template is None:
            print("Missing --descriptor_template argument")
            sys.exit()

        if args.keys_info is None:
            print("Missing --keys_info")
            sys.exit()

        try:
            keys_info = json.loads(args.keys_info)
        except json.decoder.JSONDecodeError:
            print("key_info is not valid JSON")
            sys.exit()

        sign_psbt = RequestSignPsbt()
        sign_psbt.name = args.name
        sign_psbt.descriptor_template = args.descriptor_template
        sign_psbt.keys_info.extend(keys_info)
        sign_psbt.psbt = base64.b64decode(args.psbt)
        message = Request()
        message.sign_psbt.CopyFrom(sign_psbt)

        assert message.WhichOneof("request") == "sign_psbt"
        return message.SerializeToString()

    def sign_psbt_parse_response(self, data: Optional[bytes]):
        response = Response()
        response.ParseFromString(data)
        assert response.WhichOneof("response") == "sign_psbt"

        print(f"{len(response.sign_psbt.partial_signatures)} signatures returned")

        return


if __name__ == "__main__":
    parser: ArgumentParser = stream.get_stream_arg_parser()

    exclusive_group = parser.add_mutually_exclusive_group(required=True)

    exclusive_group.add_argument("--get_version",
                                 help='Get application version',
                                 action='store_true')
    exclusive_group.add_argument("--get_master_fingerprint",
                                 help='Get the fingerprint of the master public key',
                                 action='store_true')
    exclusive_group.add_argument("--get_extended_pubkey",
                                 help='Get an extended pubkey at a given path',
                                 action='store_true')
    exclusive_group.add_argument("--register_wallet",
                                 help='Register a wallet policy',
                                 action='store_true')
    exclusive_group.add_argument("--get_wallet_address",
                                 help='Get the address for a wallet',
                                 action='store_true')
    exclusive_group.add_argument("--sign_psbt",
                                 help='Sign a psbt with a policy',
                                 action='store_true')

    # TODO: should only enable arguments for the right command
    parser.add_argument('--path', help='A BIP-32 path')
    parser.add_argument(
        '--display', help='Set if the user should validate the action on-screen', action='store_true')

    parser.add_argument(
        '--name', help='The name of a wallet policy', default="")
    parser.add_argument('--descriptor_template', help='A descriptor template')
    parser.add_argument(
        '--keys_info', help='the keys information, as a json-encoded array of strings')

    parser.add_argument('--change', type=bool,
                        help='If present, request a change address', default=False)
    parser.add_argument('--address_index', type=int,
                        help='The address index', default=0)

    parser.add_argument('--psbt', help='A base64-encoded PSBT')

    args = parser.parse_args()

    actions = ["get_version", "get_master_fingerprint", "get_extended_pubkey",
               "register_wallet", "get_wallet_address", "sign_psbt"]
    action = None
    for act in actions:
        if getattr(args, act) is True:
            action = act

    if action is None:
        print("No action or invalid action")
        sys.exit(1)

    with stream.get_streamer(args) as streamer:
        btc = Btc()

        method_name = f"{action}_prepare_request"
        prepare_request = getattr(btc, method_name)

        request = prepare_request(args)

        data: Optional[bytes] = streamer.exchange(request)

        method_name = f"{action}_parse_response"
        parse_response = getattr(btc, method_name)

        parse_response(data)