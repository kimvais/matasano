from collections import Counter
import string
import unittest
import base64
import logging

import binascii
import itertools


logger = logging.getLogger(__name__)

__author__ = 'kimvais'


def hex2base64(input):
    return base64.b64encode(binascii.unhexlify(input))


def xorwith(input, key):
    return '{:0x}'.format(int(input, 16) ^ int(key, 16))


def xorwith_char(data, char):
    output = bytes(bytearray((a ^ char) for a in data))
    return output


def english_freq(input):
    FREQ = [ord(x) for x in 'ETAOIN SHRDLU']
    MSG_CHARS = string.ascii_uppercase + string.digits + ".,- '"
    data = binascii.unhexlify(input)
    freqs = Counter(data)
    most_common = (x[0] for x in freqs.most_common(13))
    translation_table = itertools.product(FREQ, most_common)
    res = list()
    for x, y in translation_table:
        char = x ^ y
        output = xorwith_char(data, char)
        if all(chr(c) in MSG_CHARS for c in output.upper()):
            res.append(output)
    return res



class TestSet1(unittest.TestCase):
    def test_hex2base64(self):
        self.assertEquals(hex2base64(
            '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'),
                          b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    def test_xor(self):
        self.assertEquals(xorwith(
            '1c0111001f010100061a024b53535009181c',
            '686974207468652062756c6c277320657965'),
                          '746865206b696420646f6e277420706c6179')

    def test_freq(self):
        plaintext = english_freq('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        self.assertIsNotNone(plaintext)
        logger.warn('Decrypted: {}'.format(plaintext))
