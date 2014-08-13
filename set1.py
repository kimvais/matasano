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
    MSG_CHARS = string.ascii_uppercase + string.digits + ".,- '\n"
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
    return res if res else None


def xor_with_key(input, key):
    output = bytearray()
    for i, c in enumerate(input):
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
    c = Counter()
    distances = (x ^ y for x, y in zip(a, b))
    for x in distances:
        c.update(bin(x).lstrip('0b'))
    return c['1']


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
        candidates = english_freq('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        self.assertEqual(len(candidates), 1)
        logger.warn('Decrypted: {}'.format(candidates[0]))

    def test_4(self):
        results = list()
        with open('4.txt') as f:
            for line in f:
                candidates = english_freq(line.strip())
                if candidates:
                    results.extend(candidates)
        self.assertEqual(len(results), 1)
        logger.warn('Decrypted: {}'.format(results[0]))

    def test_challenge_5(self):
        input = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        output = binascii.unhexlify("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                                    "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        key = b'ICE'
        self.assertEquals(output, xor_with_key(input, key))

    def test_hamming(self):
        a = b"this is a test"
        b = b"wokka wokka!!!"
        self.assertEquals(hamming(a, b), 37)
