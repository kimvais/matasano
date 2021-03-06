from base64 import b64decode
import unittest
import logging

import binascii
import aes
from set1 import challenge_6
from set2 import challenge_12, profile_for
from tools import hex2base64, xorwith, english_freq, xor_with_key, hamming, chunk_into, pkcs7pad, unpad


KEY = b'YELLOW SUBMARINE'

with open('plaintext.txt') as f:
    PLAINTEXT = f.read().encode('ascii')

logger = logging.getLogger(__name__)
__author__ = 'kimvais'


class TestSet1(unittest.TestCase):
    def test_hex2base64(self):
        self.assertEquals(
            hex2base64(
                '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'),
            b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    def test_xor(self):
        self.assertEquals(
            xorwith(
                '1c0111001f010100061a024b53535009181c',
                '686974207468652062756c6c277320657965'),
            '746865206b696420646f6e277420706c6179')

    def test_freq(self):
        data = binascii.unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        candidate, key = english_freq(data)
        self.assertIsNotNone(candidate)
        logger.info('Decrypted: {}'.format(candidate))

    def test_challenge_4(self):
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
        data = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        output = binascii.unhexlify("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                                    "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        key = b'ICE'
        self.assertEqual(output, xor_with_key(data, key))

    def test_hamming(self):
        a = b"this is a test"
        b = b"wokka wokka!!!"
        self.assertEqual(hamming(a, b), 37)

    def test_chunking(self):
        self.assertEquals(chunk_into('foobarx', 3), ['foo', 'bar', 'x'])

    def test_challenge_7_aes_ecb(self):
        cipher = aes.ECB(KEY)
        with open('7.txt') as f:
            data = b64decode(f.read())
        self.assertEquals(unpad(cipher.decrypt(data)), PLAINTEXT)

    def test_challenge_6(self):
        self.assertEqual(PLAINTEXT, challenge_6())


class TestSet2(unittest.TestCase):
    def test_challenge_9(self):
        """
        PKCS#7 padding
        """
        data = KEY
        output = KEY + b'\x04\x04\x04\x04'
        self.assertEqual(pkcs7pad(data, 20), output)

    def test_challenge_10_ecb(self):
        e = aes.ECB(KEY)
        plaintext = b'x' * 16
        ciphertext = e.encrypt(plaintext)
        self.assertEqual(plaintext, e.decrypt(ciphertext))

    def test_challenge_10_cbc(self):
        with open('10.txt') as f:
            data = b64decode(f.read())
        c = aes.CBC(KEY, b'\x00' * 16)
        self.assertEqual(c.decrypt(data), PLAINTEXT)

    def test_challenge_10_twoway(self):
        e = aes.CBC(KEY, b'\x00' * 16)
        d = aes.CBC(KEY, b'\x00' * 16)
        x = e.encrypt(b"foobar" * 123)
        self.assertEqual(d.decrypt(x), b'foobar' * 123)

    def test_challenge_12(self):
        with open('12.txt') as f:
            plaintext = b64decode(f.read())
        cracked = challenge_12()
        self.assertEqual(cracked, plaintext)

    def test_challenge13_profile_for(self):
        self.assertRaises(ValueError, profile_for, 'email=foo&role=admin')
        # self.assertEqual(parse_profile(profile).email, 'foo@bar.com')

    def test_challenge_15_unpad(self):
        self.assertEqual(unpad(b"ICE ICE BABY\x04\x04\x04\x04"), b'ICE ICE BABY')
        self.assertRaises(ValueError, unpad, b"ICE ICE BABY\x05\x05\x05\x05")
        self.assertRaises(ValueError, unpad, b"ICE ICE BABY\x01\x02\x03\x04")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    TestSet1().test_aes_ecb()