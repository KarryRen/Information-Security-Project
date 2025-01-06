# -*- coding: utf-8 -*-
# @Time    : 2025/1/6 18:53
# @Author  : Karry Ren

""""""

import hashlib


def sha256_encrypt(message):
    """ SHA256 Encrypt. """

    # ---- Build up the sha256 object ---- #
    sha256 = hashlib.sha256()

    # ---- Update the message ---- #
    sha256.update(message.encode())

    # ---- Return the digit ---- #
    return sha256.hexdigest()


if __name__ == "__main__":
    message = "Hello, SHA256!"
    hashed_message = sha256_encrypt(message)
    print("Message:", message)
    print("SHA256 Hash:", hashed_message)
