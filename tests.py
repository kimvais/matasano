from base64 import b64decode
import unittest
import binascii
import logging
import aes
from set1 import challenge_6

from tools import hex2base64, xorwith, english_freq, xor_with_key, hamming, chunk_into
logger = logging.getLogger(__name__)
__author__ = 'kimvais'


class TestSet1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('plaintext.txt') as f:
            cls.plaintext = f.read().encode('ascii')

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
        logger.info('Decrypted: {}'.format(candidate))

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
        logger.info('Decrypted: {}'.format(results))
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

    def test_aes_ecb(self):
        cipher = aes.ECB(b'YELLOW SUBMARINE')
        with open('7.txt') as f:
            data = b64decode(f.read())
        self.assertEquals(cipher.decrypt(data), self.plaintext)

    def test_challenge_6(self):
        self.assertEqual(self.plaintext, challenge_6())

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    TestSet1().test_aes_ecb()