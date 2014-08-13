from collections import Counter
import string
import unittest
import base64
import logging
import itertools

import binascii
import math


logger = logging.getLogger(__name__)

__author__ = 'kimvais'


def hex2base64(input):
    return base64.b64encode(binascii.unhexlify(input))


def xorwith(input, key):
    return '{:0x}'.format(int(input, 16) ^ int(key, 16))


def xorwith_char(data, char):
    output = bytes(bytearray((a ^ char) for a in data))
    return output


def english_freq(input, min_score=3):
    FREQUENCIES = {'e': 12.02,
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
    if not isinstance(input, (bytes, bytearray)):
        data = binascii.unhexlify(input)
    else:
        data = input
    candidate = None
    best = min_score
    for char in range(256):
        output = xorwith_char(data, char)
        freqs = Counter(output)
        histogram = bytes(x[0] for x in freqs.most_common(13))
        if not all(chr(c) in string.printable for c in histogram):
            continue
        score = 0
        for k, v in FREQUENCIES.items():
            score += freqs[ord(k)] * v
        score = score / len(output)
        if score > best:
            logger.warning('Found a candidate histogram: {} with score {} - {}'.format(bytes(histogram), score, output))
            best = score
            candidate = (output, char)
    return candidate


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
        input = binascii.unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        candidate, key = english_freq(input)
        self.assertIsNotNone(candidate)
        logger.warning('Decrypted: {}'.format(candidate))

    def test_4(self):
        results = list()
        with open('4.txt') as f:
            for line in f:
                try:
                    candidate, key = english_freq(binascii.unhexlify(line.strip()))
                except TypeError:
                    continue
                else:
                    results = candidate
        logger.warning('Decrypted: {}'.format(results))
        self.assertIsNotNone(results)

    def test_challenge_5(self):
        input = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        output = binascii.unhexlify("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                                    "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        key = b'ICE'
        self.assertEqual(output, xor_with_key(input, key))

    def test_hamming(self):
        a = b"this is a test"
        b = b"wokka wokka!!!"
        self.assertEqual(hamming(a, b), 37)


    def test_chunking(self):
        self.assertEquals(chunk_into('foobarx', 3), ['foo', 'bar', 'x'])


def chunk_into(data, size):
    ret = list()
    for i in range(math.ceil(len(data) / size)):
        ret.append(data[i * size:(i + 1) * size])
    return ret


def main():
    with open('6.txt') as f:
        data = base64.b64decode(f.read())
    keysize_candidates = list()
    for keysize in range(1, 30):
        chunks = chunk_into(data, keysize)
        pairs = itertools.combinations(chunks[:4], 2)
        score = 0
        for a, b in pairs:
            hscore = hamming(a, b)
            logger.fatal(hscore)
            score += hscore / keysize
        score = score / 4
        keysize_candidates.append((keysize, score))
    keysize_probability = sorted(keysize_candidates, key=lambda x: x[1])
    logger.info("Probable keysizes: {}".format(keysize_probability[:5]))
    for keysize, score in keysize_probability[:3]:
        key_ints = list()
        logger.debug(keysize)
        chunks = chunk_into(data, keysize)
        transposed = zip(*chunks[:-1])
        for x in transposed:
            try:
                _, key_int = english_freq(bytes(x))
                key_ints.append(key_int)
            except TypeError:
                break

        if len(key_ints) == keysize:
            print('Decrypted:')
            print(xor_with_key(data, bytes(key_ints)).decode('ascii'))
            return



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
