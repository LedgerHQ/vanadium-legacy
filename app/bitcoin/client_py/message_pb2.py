# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: message.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rmessage.proto\"\x13\n\x11RequestGetVersion\"%\n\x12ResponseGetVersion\x12\x0f\n\x07version\x18\x01 \x01(\t\"\x1d\n\x1bRequestGetMasterFingerprint\"3\n\x1cResponseGetMasterFingerprint\x12\x13\n\x0b\x66ingerprint\x18\x01 \x01(\r\"?\n\x18RequestGetExtendedPubkey\x12\x0f\n\x07\x64isplay\x18\x01 \x01(\x08\x12\x12\n\nbip32_path\x18\x02 \x03(\r\"+\n\x19ResponseGetExtendedPubkey\x12\x0e\n\x06pubkey\x18\x01 \x01(\t\"U\n\x15RequestRegisterWallet\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x1b\n\x13\x64\x65scriptor_template\x18\x02 \x01(\t\x12\x11\n\tkeys_info\x18\x03 \x03(\t\"@\n\x16ResponseRegisterWallet\x12\x11\n\twallet_id\x18\x01 \x01(\x0c\x12\x13\n\x0bwallet_hmac\x18\x02 \x01(\x0c\"\xb9\x01\n\x17RequestGetWalletAddress\x12\x0f\n\x07\x64isplay\x18\x01 \x01(\x08\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x1b\n\x13\x64\x65scriptor_template\x18\x03 \x01(\t\x12\x11\n\tkeys_info\x18\x04 \x03(\t\x12\x18\n\x0bwallet_hmac\x18\x05 \x01(\x0cH\x00\x88\x01\x01\x12\x0e\n\x06\x63hange\x18\x06 \x01(\x08\x12\x15\n\raddress_index\x18\x07 \x01(\rB\x0e\n\x0c_wallet_hmac\"+\n\x18ResponseGetWalletAddress\x12\x0f\n\x07\x61\x64\x64ress\x18\x01 \x01(\t\"\x87\x01\n\x0fRequestSignPsbt\x12\x0c\n\x04psbt\x18\x01 \x01(\x0c\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x1b\n\x13\x64\x65scriptor_template\x18\x03 \x01(\t\x12\x11\n\tkeys_info\x18\x04 \x03(\t\x12\x18\n\x0bwallet_hmac\x18\x05 \x01(\x0cH\x00\x88\x01\x01\x42\x0e\n\x0c_wallet_hmac\"L\n\x10PartialSignature\x12\x11\n\tsignature\x18\x01 \x01(\x0c\x12\x12\n\npublic_key\x18\x02 \x01(\x0c\x12\x11\n\tleaf_hash\x18\x03 \x01(\x0c\"A\n\x10ResponseSignPsbt\x12-\n\x12partial_signatures\x18\x01 \x03(\x0b\x32\x11.PartialSignature\"\x1d\n\x1bRequestGetLatestBlockHeader\"X\n\x1cResponseGetLatestBlockHeader\x12\x0e\n\x06height\x18\x01 \x01(\r\x12\x12\n\nblock_hash\x18\x02 \x01(\x0c\x12\x14\n\x0c\x62lock_header\x18\x03 \x01(\x0c\"W\n\x1bRequestSetLatestBlockHeader\x12\x0e\n\x06height\x18\x01 \x01(\r\x12\x12\n\nblock_hash\x18\x02 \x01(\x0c\x12\x14\n\x0c\x62lock_header\x18\x03 \x01(\x0c\"\x1e\n\x1cResponseSetLatestBlockHeader\"\"\n\rResponseError\x12\x11\n\terror_msg\x18\x01 \x01(\t\"\xcd\x03\n\x07Request\x12)\n\x0bget_version\x18\x01 \x01(\x0b\x32\x12.RequestGetVersionH\x00\x12>\n\x16get_master_fingerprint\x18\x02 \x01(\x0b\x32\x1c.RequestGetMasterFingerprintH\x00\x12\x38\n\x13get_extended_pubkey\x18\x03 \x01(\x0b\x32\x19.RequestGetExtendedPubkeyH\x00\x12\x31\n\x0fregister_wallet\x18\x04 \x01(\x0b\x32\x16.RequestRegisterWalletH\x00\x12\x36\n\x12get_wallet_address\x18\x05 \x01(\x0b\x32\x18.RequestGetWalletAddressH\x00\x12%\n\tsign_psbt\x18\x06 \x01(\x0b\x32\x10.RequestSignPsbtH\x00\x12?\n\x17get_latest_block_header\x18\x07 \x01(\x0b\x32\x1c.RequestGetLatestBlockHeaderH\x00\x12?\n\x17set_latest_block_header\x18\x08 \x01(\x0b\x32\x1c.RequestSetLatestBlockHeaderH\x00\x42\t\n\x07request\"\xf8\x03\n\x08Response\x12*\n\x0bget_version\x18\x01 \x01(\x0b\x32\x13.ResponseGetVersionH\x00\x12?\n\x16get_master_fingerprint\x18\x02 \x01(\x0b\x32\x1d.ResponseGetMasterFingerprintH\x00\x12\x39\n\x13get_extended_pubkey\x18\x03 \x01(\x0b\x32\x1a.ResponseGetExtendedPubkeyH\x00\x12\x32\n\x0fregister_wallet\x18\x04 \x01(\x0b\x32\x17.ResponseRegisterWalletH\x00\x12\x37\n\x12get_wallet_address\x18\x05 \x01(\x0b\x32\x19.ResponseGetWalletAddressH\x00\x12&\n\tsign_psbt\x18\x06 \x01(\x0b\x32\x11.ResponseSignPsbtH\x00\x12@\n\x17get_latest_block_header\x18\x07 \x01(\x0b\x32\x1d.ResponseGetLatestBlockHeaderH\x00\x12@\n\x17set_latest_block_header\x18\x08 \x01(\x0b\x32\x1d.ResponseSetLatestBlockHeaderH\x00\x12\x1f\n\x05\x65rror\x18\t \x01(\x0b\x32\x0e.ResponseErrorH\x00\x42\n\n\x08responseb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'message_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _REQUESTGETVERSION._serialized_start=17
  _REQUESTGETVERSION._serialized_end=36
  _RESPONSEGETVERSION._serialized_start=38
  _RESPONSEGETVERSION._serialized_end=75
  _REQUESTGETMASTERFINGERPRINT._serialized_start=77
  _REQUESTGETMASTERFINGERPRINT._serialized_end=106
  _RESPONSEGETMASTERFINGERPRINT._serialized_start=108
  _RESPONSEGETMASTERFINGERPRINT._serialized_end=159
  _REQUESTGETEXTENDEDPUBKEY._serialized_start=161
  _REQUESTGETEXTENDEDPUBKEY._serialized_end=224
  _RESPONSEGETEXTENDEDPUBKEY._serialized_start=226
  _RESPONSEGETEXTENDEDPUBKEY._serialized_end=269
  _REQUESTREGISTERWALLET._serialized_start=271
  _REQUESTREGISTERWALLET._serialized_end=356
  _RESPONSEREGISTERWALLET._serialized_start=358
  _RESPONSEREGISTERWALLET._serialized_end=422
  _REQUESTGETWALLETADDRESS._serialized_start=425
  _REQUESTGETWALLETADDRESS._serialized_end=610
  _RESPONSEGETWALLETADDRESS._serialized_start=612
  _RESPONSEGETWALLETADDRESS._serialized_end=655
  _REQUESTSIGNPSBT._serialized_start=658
  _REQUESTSIGNPSBT._serialized_end=793
  _PARTIALSIGNATURE._serialized_start=795
  _PARTIALSIGNATURE._serialized_end=871
  _RESPONSESIGNPSBT._serialized_start=873
  _RESPONSESIGNPSBT._serialized_end=938
  _REQUESTGETLATESTBLOCKHEADER._serialized_start=940
  _REQUESTGETLATESTBLOCKHEADER._serialized_end=969
  _RESPONSEGETLATESTBLOCKHEADER._serialized_start=971
  _RESPONSEGETLATESTBLOCKHEADER._serialized_end=1059
  _REQUESTSETLATESTBLOCKHEADER._serialized_start=1061
  _REQUESTSETLATESTBLOCKHEADER._serialized_end=1148
  _RESPONSESETLATESTBLOCKHEADER._serialized_start=1150
  _RESPONSESETLATESTBLOCKHEADER._serialized_end=1180
  _RESPONSEERROR._serialized_start=1182
  _RESPONSEERROR._serialized_end=1216
  _REQUEST._serialized_start=1219
  _REQUEST._serialized_end=1680
  _RESPONSE._serialized_start=1683
  _RESPONSE._serialized_end=2187
# @@protoc_insertion_point(module_scope)
