import base64
import logging
import aes
from tests import KEY
from tools import english_freq, xor_with_key

logger = logging.getLogger('Challenge 20')
__author__ = 'kimvais'

CIPHERTEXTS = list()

with open('20.txt') as f:
    for line in f:
        CIPHERTEXTS.append(aes.CTR(KEY).encrypt(base64.b64decode(line)))

MIN_LEN = len(min(CIPHERTEXTS, key=len))


def main():
    piecemeal = [bytes(x) for x in zip(*CIPHERTEXTS)]
    keystream = list()
    for x in piecemeal:
        c = english_freq(x)
        keystream.append(c[1])
    for ct in CIPHERTEXTS:
        logger.info(xor_with_key(ct, bytes(keystream)))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s.%(funcName)s:[%(lineno)s]: %(message)s')
    logger.info(main())
