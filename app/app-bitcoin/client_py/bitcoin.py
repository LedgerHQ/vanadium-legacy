#!/usr/bin/env python3

import json
import os
import sys

from message_pb2 import RequestGetVersion, RequestGetMasterFingerprint, Request, Response

# TODO: make a proper package for the stream.py module
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "host"))

import stream  # noqa: E402


class Btc:
    def get_version_prepare_request(self):
        get_version = RequestGetVersion()
        message = Request()
        message.get_version.CopyFrom(get_version)
        assert message.WhichOneof("request") == "get_version"
        return message.SerializeToString()

    def get_version_parse_response(self, data):
        response = Response()

        print("Response:")
        print(response)  # TODO: remove

        response.ParseFromString(data)
        assert response.WhichOneof("response") == "get_version"
        print(f"version: {response.get_version.version}")
        return

    def get_master_fingerprint_prepare_request(self):
        get_master_fingerprint = RequestGetMasterFingerprint()
        message = Request()
        message.get_master_fingerprint.CopyFrom(get_master_fingerprint)
        assert message.WhichOneof("request") == "get_master_fingerprint"
        return message.SerializeToString()

    def get_master_fingerprint_parse_response(self, data):
        response = Response()
        response.ParseFromString(data)
        assert response.WhichOneof("response") == "get_master_fingerprint"
        fpr_hex = '{:08x}'.format(response.get_master_fingerprint.fingerprint)
        print(f"master fpr: {fpr_hex}")
        return


if __name__ == "__main__":
    actions = ["get_version", "get_master_fingerprint"]

    parser = stream.get_stream_arg_parser()
    parser.add_argument("--action", default="get_version", choices=actions)
    args = parser.parse_args()

    with stream.get_streamer(args) as streamer:
        btc = Btc()

        method_name = f"{args.action}_prepare_request"
        prepare_request = getattr(btc, method_name)

        request = prepare_request()

        data = streamer.exchange(request)

        method_name = f"{args.action}_parse_response"
        parse_response = getattr(btc, method_name)

        parse_response(data)
