# -*- coding: utf-8 -*-
import hashlib
import hmac
import base64
import time
import random
import string
import secrets


def generate_key(key_long: int = 2048) -> str:
    # chars = string.ascii_letters + string.digits + "+-"
    chars = string.ascii_letters + string.digits + string.punctuation
    key = "".join(random.choice(chars) for _ in range(key_long))
    return key


def generate_key_plus(key_long: int = 2048) -> str:
    # chars = string.ascii_letters + string.digits + "+-"
    chars = string.ascii_letters + string.digits + string.punctuation
    key = "".join(secrets.choice(chars) for _ in range(key_long))
    return key


def generate_totp(key: str, timestamp: int, window: int = 30000, token_long: int = 128) -> str:
    key_bytes = key.encode()
    timestep = int(int(timestamp) / window)
    hash_algorithms = [hashlib.sha256, hashlib.sha384, hashlib.sha512, hashlib.md5, hashlib.sha1, hashlib.sha224]
    macs = b""
    for hash_algorithm in hash_algorithms:
        mac = hmac.new(key_bytes, timestep.to_bytes(8, "big"), hash_algorithm).digest()
        macs += mac
        mac = hmac.new(key_bytes, timestep.to_bytes(8, "little"), hash_algorithm).digest()
        macs += mac
    encoded_macs = base64.b64encode(macs).rstrip(b"=")
    offset = 0
    token = encoded_macs[offset:offset + token_long].decode()
    token = token.replace("/", "-")
    token = token.replace("=", "+")
    return token


def generate_totp_plus(key: str, timestamp: int, window: int = 30000, token_long: int = 128) -> str:
    key_bytes = key.encode()
    timestep = int(int(timestamp) / window)
    hash_algorithms = [hashlib.sha256, hashlib.sha384, hashlib.sha512, hashlib.md5, hashlib.sha1, hashlib.sha224,
                       hashlib.sha3_256, hashlib.sha3_384, hashlib.sha3_512, hashlib.sha3_224]
    macs = b""
    for hash_algorithm in hash_algorithms:
        mac = hmac.new(hmac.new(key_bytes, timestep.to_bytes(8, "big"), hash_algorithm).digest(),
                       timestep.to_bytes(8, "little"), hash_algorithm).digest()
        macs += mac
        mac = hmac.new(key_bytes, timestep.to_bytes(8, "big"), hash_algorithm).digest()
        macs += mac
        mac = hmac.new(hmac.new(key_bytes, timestep.to_bytes(8, "little"), hash_algorithm).digest(),
                       timestep.to_bytes(8, "big"), hash_algorithm).digest()
        macs += mac
        mac = hmac.new(key_bytes, timestep.to_bytes(8, "little"), hash_algorithm).digest()
        macs += mac
    encoded_macs = base64.b64encode(macs).rstrip(b"=")
    offset = 0
    token = encoded_macs[offset:offset + token_long].decode()
    token = token.replace("/", "-")
    token = token.replace("=", "+")
    return token


def generate_totp_now(key: str, window: int = 30000, token_long: int = 128) -> str:
    timestamp = int(time.time() * 1000)
    return generate_totp(key, timestamp, window=window, token_long=token_long)


def generate_totp_plus_now(key: str, window: int = 30000, token_long: int = 128) -> str:
    timestamp = int(time.time() * 1000)
    return generate_totp_plus(key, timestamp, window=window, token_long=token_long)


# print("====================================================================================================")
# debug_key = generate_key()
# print(debug_key)
# print("====================================================================================================")
# debug_key = generate_key_plus()
# print(debug_key)
# print("====================================================================================================")
# debug_key = "The Key String"
# token = generate_totp_now(debug_key)
# print(token)
# print("")
# token = generate_totp_plus_now(debug_key)
# print(token)
# print("====================================================================================================")


def generate_totp_simple(key: str, timestamp: int, window: int = 30000, token_long: int = 128) -> str:
    key_bytes = key.encode()
    timestep = int(int(timestamp) / window)
    hash_algorithms = [hashlib.sha256(), hashlib.sha384(), hashlib.sha512()]
    macs = bytes()
    for hash_algorithm in hash_algorithms:
        hash_algorithm.update(timestep.to_bytes(8, "big") + key_bytes + timestep.to_bytes(8, "little"))
        hash_algorithm.update(timestep.to_bytes(8, "little") + macs + timestep.to_bytes(8, "big"))
        macs = macs + hash_algorithm.digest()
    encoded_macs = base64.b64encode(macs).rstrip(b"=")
    offset = 0
    token = encoded_macs[offset:offset + token_long].decode()
    token = token.replace("/", "-")
    token = token.replace("=", "+")
    return token


def generate_totp_simple_now(key: str, window: int = 30000, token_long: int = 128) -> str:
    timestamp = int(time.time() * 1000)
    return generate_totp_simple(key, timestamp, window=window, token_long=token_long)


def generate_totp_simplest(key: str, timestamp: int, window: int = 30000, token_long: int = 128) -> str:
    key_bytes = key.encode()
    timestep = int(int(timestamp) / window)
    hash_algorithm = hashlib.sha512()
    macs = bytes()
    hash_algorithm.update(timestep.to_bytes(8, "big") + key_bytes + timestep.to_bytes(8, "little"))
    hash_algorithm.update(timestep.to_bytes(8, "little") + macs + timestep.to_bytes(8, "big"))
    macs = macs + hash_algorithm.digest()
    encoded_macs = base64.b64encode(macs).rstrip(b"=")
    offset = 0
    token = encoded_macs[offset:offset + token_long].decode()
    token = token.replace("/", "-")
    token = token.replace("=", "+")
    return token


def generate_totp_simplest_now(key: str, window: int = 30000, token_long: int = 128) -> str:
    timestamp = int(time.time() * 1000)
    return generate_totp_simplest(key, timestamp, window=window, token_long=token_long)
