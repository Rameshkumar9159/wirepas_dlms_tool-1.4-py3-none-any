# Copyright 2023 Wirepas Ltd licensed under Apache License, Version 2.0
#
# See file LICENSE for full license details.
#
from enum import auto, Enum


class ErrorCodeEnum(Enum):
    """ Error code of the DLMS responses from meters. """
    # The message is valid and translatable.
    RES_OK = 0

    # The message is invalid and not translatable.
    RES_ERROR = auto()

    # The message has not been received and a timeout error was raised.
    RES_TIMEOUT = auto()

    # The message is invalid.
    RES_INVALID_MESSAGE = auto()

    # The message can't be parsed as the keys provided are not the ones used to encryt it.
    RES_INVALID_KEYS = auto()

    # The message is well formed and decrypted but it's an error response from the meter.
    RES_MESSAGE_IS_AN_ERROR = auto()
