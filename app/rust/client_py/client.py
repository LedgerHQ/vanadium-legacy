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
from prompt_toolkit.history import FileHistory

from argparse import ArgumentParser
from typing import Optional

from boiler_pb2 import RequestGetVersion, RequestGetAppName, RequestGetPubKey, RequestSignTx, Request, Response
from util import bip32_path_to_list

# TODO: make a proper package for the stream.py module
sys.path.append(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "..", "..", "..", "host"))

import stream  # noqa: E402

logging.basicConfig(filename='dump.log', filemode='w+', level=logging.DEBUG)

ACK = b'\x42'

class dotdict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


# TODO: separate Client class from the vanadium cli
class Client:
    def __init__(self, streamer):
        self.streamer = streamer

    def exchange_message(self, data: bytes) -> bytes:
        # Encode the length of the data as a 4-byte big-endian integer
        length_encoded = len(data).to_bytes(4, 'big')

        # Construct the complete message
        full_message = length_encoded + data
        response_data = b''

        # Send the message in chunks of up to 256 bytes
        for i in range(0, len(full_message), 256):
            chunk = full_message[i:i+256]
            response = self.streamer.exchange(chunk)

            # If we're sending the last chunk, the response will be the start of the actual response
            # Otherwise, the response should be a single byte 0x42.
            if i + 256 >= len(full_message):
                response_data = response
            elif response != ACK:
                raise ValueError('Unexpected data received before message transmission was complete.')

        if len(response_data) < 4:
            raise ValueError('Incomplete length received in response.')

        # Extract the expected length of the full response
        response_length = int.from_bytes(response_data[:4], 'big')
        response_data = response_data[4:]

        # Continue receiving data until the full response is retrieved
        while len(response_data) < response_length:
            chunk = self.streamer.exchange(ACK)  # Request more of the response
            response_data += chunk

        # Return the complete response
        return response_data[:response_length]

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
    
    def get_appname_prepare_request(self, args: dotdict):
        get_appname = RequestGetAppName()
        message = Request()
        message.get_appname.CopyFrom(get_appname)
        assert message.WhichOneof("request") == "get_appname"
        return message.SerializeToString()

    def get_appname_parse_response(self, response):
        assert response.WhichOneof("response") == "get_appname"
        print(f"appname: {response.get_appname.appname}")
        return
    
    def get_pubkey_prepare_request(self, args: dotdict):
        if args.path is None:
            raise ValueError("Missing 'path' argument")

        get_pubkey = RequestGetPubKey()
        display_value = args.get("display", "False")
        get_pubkey.display = display_value.lower() == "true"
        get_pubkey.path.extend(bip32_path_to_list(args.path))
        message = Request()
        message.get_pubkey.CopyFrom(get_pubkey)

        assert message.WhichOneof("request") == "get_pubkey"
        return message.SerializeToString()
    
    def get_pubkey_parse_response(self, response):
        assert response.WhichOneof("response") == "get_pubkey"
        print(f"pubkey (65): 0x{response.get_pubkey.pubkey}")
        print(f"chaincode (32): 0x{response.get_pubkey.chaincode}")
        return
    
    def sign_tx_prepare_request(self, args: dotdict):
        tx = RequestSignTx()
        tx.path.extend(bip32_path_to_list(args.get("path", "m/44'/1'/0'/0/0")))
        tx.nonce = 1
        tx.value = int(args.get("ammount", "666"))
        tx.address = args.get("to", "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae")
        tx.memo = args.get("memo", "For u EthDev")
        message = Request()
        message.sign_tx.CopyFrom(tx)

        assert message.WhichOneof("request") == "sign_tx"
        return message.SerializeToString()
    
    def sign_tx_parse_response(self, response):
        assert response.WhichOneof("response") == "sign_tx"
        print(f"hash: {response.sign_tx.hash}")
        print(f"len: {response.sign_tx.siglen}")
        print(f"signature (DER): 0x{response.sign_tx.sig}")
        print(f"v: 0x{response.sign_tx.v}")
        return

        

class ActionArgumentCompleter(Completer):
    ACTION_ARGUMENTS = {
        "get_version": [],
        "get_appname": [],
        "get_pubkey": [ "display", "path="],
        "sign_tx": ["path", "to", "amount", "memo"],
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
    
    actions = ["get_version", "get_appname", "get_pubkey", "sign_tx"]

    completer = ActionArgumentCompleter()
    # Create a history object
    history = FileHistory('.cli-history')
    
    with stream.get_streamer(args) as streamer:
        cli = Client(streamer)

        last_command_time = None
        while True:
            input_line = prompt(">> ", history=history, completer=completer)

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
                key, value = item.split('=', 1)
                args_dict[key] = value

            if action == "time":
                print("Runtime of last command:", last_command_time)
                continue

            if action not in actions:
                print("Invalid action")
                continue

            try:
                method_name = f"{action}_prepare_request"
                prepare_request = getattr(cli, method_name)

                request = prepare_request(args_dict)

                time_start = time.time()
                data: Optional[bytes] = cli.exchange_message(request)
                last_command_time = time.time() - time_start

                response = Response()
                response.ParseFromString(data)

                if response.WhichOneof("response") == "error":
                    print(f"Error: {response.error.error_msg}")
                else:
                    method_name = f"{action}_parse_response"
                    parse_response = getattr(cli, method_name)

                    parse_response(response)
            except Exception as e:
                print(f"An error occurred: {str(e)}")
                raise e
