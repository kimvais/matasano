import base64
from collections import Counter
import string
import logging

import math
import binascii


logger = logging.getLogger(__name__)

__author__ = 'kimvais'


def hex2base64(data):
    return base64.b64encode(binascii.unhexlify(data))


def xorwith(data, key):
    return '{:0x}'.format(int(data, 16) ^ int(key, 16))


def xorwith_char(data, char):
    output = bytes(bytearray((a ^ char) for a in data))
    return output


def english_freq(data, min_score=3):
    frequencies = {'e': 12.02,
                   't': 9.10,
                   'a': 8.12,
                   'o': 7.68,
                   'i': 7.31,
                   'n': 6.95,
                   ' ': 6.10,
                   's': 6.28,
                   'r': 6.02,
                   'h': 5.92,
                   'd': 4.32,
                   'l': 3.98,
                   'u': 2.88,
                   'c': 2.71,
                   'm': 2.61,
                   'f': 2.30,
                   'y': 2.11,
                   'w': 2.09,
                   'g': 2.03,
                   'p': 1.82,
                   'b': 1.49,
                   'v': 1.11,
                   'k': 0.69,
                   'x': 0.17,
                   'q': 0.11,
                   'j': 0.10,
                   'z': 0.07}
    if not isinstance(data, (bytes, bytearray)):
        data = binascii.unhexlify(data)
    else:
        data = data
    candidate = None
    best = min_score
    for char in range(256):
        output = xorwith_char(data, char)
        freqs = Counter(output)
        histogram = bytes(x[0] for x in freqs.most_common(13))
        if not all(chr(c) in string.printable for c in histogram):
            continue
        score = 0
        for k, v in frequencies.items():
            score += freqs[ord(k)] * v
        score = score / len(output)
        if score > best:
            logger.info('Found a candidate histogram: {} with score {} - {}'.format(bytes(histogram), score, output))
            best = score
            candidate = (output, char)
    return candidate


def xor_with_key(data, key):
    output = bytearray()
    for i, c in enumerate(data):
        key_idx = i % len(key)
        output.append(key[key_idx] ^ c)
    return bytes(output)


def hamming(a, b):
    """
    Calculates the edit distance / hamming distance of two input streams a and b
    :param a: bytes()
    :param b: bytes()
    :return: int()
    """
    assert len(a) == len(b)
    distances = (x ^ y for x, y in zip(a, b))
    c = Counter()
    for x in distances:
        c.update(bin(x).lstrip('0b'))
    return c['1']


def chunk_into(data, size):
    ret = list()
    for i in range(math.ceil(len(data) / size)):
        ret.append(data[i * size:(i + 1) * size])
    return ret


def pkcs7pad(data, blocksize):
    assert isinstance(data, bytes)
    padlen = blocksize - len(data) % blocksize
    if padlen == 0:
        padlen = blocksize
    return data + padlen * bytes((padlen,))


def unpad(plain):
    padding = plain[-plain[-1]:]
    if len(set(padding)) != 1:
        raise ValueError('Invalid padding: {}'.format(padding))
    return plain[:-plain[-1]]


class UserProfile(dict):
    def __init__(self, d):
        super().__init__()
        self.__dict__ = self
        for k, v in d.items():
            if not isinstance(v, (bytes, int)):
                v = v.encode('ascii')
            self[k] = v

    def serialize(self):
        return b'email=' + self.email + '&uid={}'.format(self.uid).encode('ascii') + b'&role=' + self.role









