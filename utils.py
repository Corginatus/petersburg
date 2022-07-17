from typing import Iterable

STRING_LIKE_TYPES = (str, bytes, bytearray)


def stringify(value):
    if isinstance(value, Iterable) and not isinstance(value, STRING_LIKE_TYPES):
        return ','.join(map(str, value))
    return value


def stringify_values(dictionary):
    return {key: stringify(value) for key, value in dictionary.items()}

