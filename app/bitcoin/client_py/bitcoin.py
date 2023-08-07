#!/usr/bin/env python3

import logging
import os
import sys
import json
import base64
import shlex
import time

from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion

from argparse import ArgumentParser
from typing import Optional

from message_pb2 import RequestGetVersion, RequestGetMasterFingerprint, RequestGetExtendedPubkey, RequestRegisterWallet, RequestGetWalletAddress, RequestSignPsbt, Request, Response
from util import bip32_path_to_list

# TODO: make a proper package for the stream.py module
sys.path.append(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "..", "..", "..", "host"))

import stream  # noqa: E402

logging.basicConfig(filename='bitcoin.log', level=logging.DEBUG)


class dotdict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


# TODO: separate BTC class from the cli
class Btc:
    def get_version_prepare_request(self, args: dotdict):
        get_version = RequestGetVersion()
        message = Request()
        message.get_version.CopyFrom(get_version)
        assert message.WhichOneof("request") == "get_version"
        return message.SerializeToString()

    def get_version_parse_response(self, response):
        assert response.WhichOneof("response") == "get_version"
        print(f"version: {response.get_version.version}")
        return

    def get_master_fingerprint_prepare_request(self, args: dotdict):
        get_master_fingerprint = RequestGetMasterFingerprint()
        message = Request()
        message.get_master_fingerprint.CopyFrom(get_master_fingerprint)
        assert message.WhichOneof("request") == "get_master_fingerprint"
        return message.SerializeToString()

    def get_master_fingerprint_parse_response(self, response):
        assert response.WhichOneof("response") == "get_master_fingerprint"
        fpr_hex = '{:08x}'.format(response.get_master_fingerprint.fingerprint)
        print(f"master fpr: {fpr_hex}")
        return

    def get_extended_pubkey_prepare_request(self, args: dotdict):
        if args.path is None:
            raise ValueError("Missing 'path' argument")

        get_extended_pubkey = RequestGetExtendedPubkey()
        get_extended_pubkey.display = args.get("display", False)
        get_extended_pubkey.bip32_path.extend(bip32_path_to_list(args.path))
        message = Request()
        message.get_extended_pubkey.CopyFrom(get_extended_pubkey)

        assert message.WhichOneof("request") == "get_extended_pubkey"
        return message.SerializeToString()

    def get_extended_pubkey_parse_response(self, response):
        assert response.WhichOneof("response") == "get_extended_pubkey"
        print(f"pubkey: {response.get_extended_pubkey.pubkey}")
        return

    def register_wallet_prepare_request(self, args: dotdict):
        if args.name == "":
            raise ValueError("Missing or empty --name argument")

        if args.descriptor_template is None:
            raise ValueError("Missing --descriptor_template argument")

        if args.keys_info is None:
            raise ValueError("Missing --keys_info")

        try:
            keys_info = json.loads(args.keys_info)
        except json.decoder.JSONDecodeError:
            raise RuntimeError("key_info is not valid JSON")

        register_wallet = RequestRegisterWallet()
        register_wallet.name = args.name
        register_wallet.descriptor_template = args.descriptor_template
        register_wallet.keys_info.extend(keys_info)
        message = Request()
        message.register_wallet.CopyFrom(register_wallet)

        assert message.WhichOneof("request") == "register_wallet"
        return message.SerializeToString()

    def register_wallet_parse_response(self, response):
        assert response.WhichOneof("response") == "register_wallet"
        print(f"id: {response.register_wallet.wallet_id}")
        print(f"hmac: {response.register_wallet.wallet_hmac}")
        return

    def get_wallet_address_prepare_request(self, args: dotdict):
        if args.descriptor_template is None:
            raise ValueError("Missing --descriptor_template argument")

        if args.keys_info is None:
            raise ValueError("Missing --keys_info")

        try:
            keys_info = json.loads(args.keys_info)
        except json.decoder.JSONDecodeError:
            raise RuntimeError("key_info is not valid JSON")

        get_wallet_address = RequestGetWalletAddress()
        get_wallet_address.name = args.get("name", "")
        get_wallet_address.descriptor_template = args.descriptor_template
        get_wallet_address.keys_info.extend(keys_info)
        get_wallet_address.change = int(args.get("change", "0"))
        get_wallet_address.address_index = int(args.get("address_index", "0"))
        message = Request()
        message.get_wallet_address.CopyFrom(get_wallet_address)

        assert message.WhichOneof("request") == "get_wallet_address"
        return message.SerializeToString()

    def get_wallet_address_parse_response(self, response):
        assert response.WhichOneof("response") == "get_wallet_address"
        print(f"address: {response.get_wallet_address.address}")
        return

    def sign_psbt_prepare_request(self, args: dotdict):
        if args.psbt is None:
            raise ValueError("Missing --psbt argument")

        if args.descriptor_template is None:
            raise ValueError("Missing --descriptor_template argument")

        if args.keys_info is None:
            raise ValueError("Missing --keys_info")

        try:
            keys_info = json.loads(args.keys_info)
        except json.decoder.JSONDecodeError:
            raise ValueError("key_info is not valid JSON")

        sign_psbt = RequestSignPsbt()
        sign_psbt.name = args.get("name", "")
        sign_psbt.descriptor_template = args.descriptor_template
        sign_psbt.keys_info.extend(keys_info)
        sign_psbt.psbt = base64.b64decode(args.psbt)
        message = Request()
        message.sign_psbt.CopyFrom(sign_psbt)

        assert message.WhichOneof("request") == "sign_psbt"
        return message.SerializeToString()

    def sign_psbt_parse_response(self, response):
        response = Response()
        response.ParseFromString(data)
        assert response.WhichOneof("response") == "sign_psbt"

        n_sigs = len(response.sign_psbt.partial_signatures)
        print(f"{n_sigs} signatures returned")
        for partial_sig in response.sign_psbt.partial_signatures:
            print(f"Pubkey: {partial_sig.public_key.hex()}")
            print(f"Signature: {partial_sig.signature.hex()}")

        return


class ActionArgumentCompleter(Completer):
    ACTION_ARGUMENTS = {
        "get_version": [],
        "get_master_fingerprint": [],
        "get_extended_pubkey": ["display", "path="],
        "register_wallet": ["name=", "descriptor_template=", "keys_info="],
        "get_wallet_address": ["name=", "descriptor_template=", "keys_info=", "change=", "address_index="],
        "sign_psbt": ["name=", "descriptor_template=", "keys_info=", "psbt="],
    }

    def get_completions(self, document, complete_event):
        word_before_cursor = document.get_word_before_cursor(WORD=True)

        if ' ' not in document.text:
            # user is typing the action
            for action in self.ACTION_ARGUMENTS.keys():
                if action.startswith(word_before_cursor):
                    yield Completion(action, start_position=-len(word_before_cursor))
        else:
            # user is typing an argument, find which are valid
            action = document.text.split()[0]
            for argument in self.ACTION_ARGUMENTS.get(action, []):
                if argument not in document.text and argument.startswith(word_before_cursor):
                    yield Completion(argument, start_position=-len(word_before_cursor))


if __name__ == "__main__":
    parser: ArgumentParser = stream.get_stream_arg_parser()
    args = parser.parse_args()

    actions = ["get_version", "get_master_fingerprint", "get_extended_pubkey",
               "register_wallet", "get_wallet_address", "sign_psbt"]

    completer = ActionArgumentCompleter()

    with stream.get_streamer(args) as streamer:

        btc = Btc()

        # Run get_version to make sure the app starts
        streamer.exchange(btc.get_version_prepare_request(dotdict({})))

        last_command_time = None
        while True:
            input_line = prompt("₿ ", completer=completer)

            # Split into a command and the list of arguments
            try:
                input_line_list = shlex.split(input_line)
            except ValueError as e:
                print(f"Invalid command: {str(e)}")
                continue

            # Ensure input_line_list is not empty
            if input_line_list:
                action = input_line_list[0]
            else:
                print("Invalid command")
                continue

            # Get the necessary arguments from input_command_list
            args_dict = dotdict({})
            for item in input_line_list[1:]:
                key, value = item.split('=')
                args_dict[key] = value

            if action == "time":
                print("Runtime of last command:", last_command_time)
                continue

            if action not in actions:
                print("Invalid action")
                continue

            try:
                method_name = f"{action}_prepare_request"
                prepare_request = getattr(btc, method_name)

                request = prepare_request(args_dict)

                time_start = time.time()
                data: Optional[bytes] = streamer.exchange(request)
                last_command_time = time.time() - time_start

                response = Response()
                response.ParseFromString(data)

                if response.WhichOneof("response") == "error":
                    print(f"Error: {response.error.error_msg}")
                else:
                    method_name = f"{action}_parse_response"
                    parse_response = getattr(btc, method_name)

                    parse_response(response)
            except Exception as e:
                print(f"An error occurred: {str(e)}")
