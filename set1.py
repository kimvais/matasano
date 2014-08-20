import base64
import logging

import itertools
from tools import english_freq, xor_with_key, hamming, chunk_into


logger = logging.getLogger(__name__)

__author__ = 'kimvais'


def challenge_6():
    with open('6.txt') as f:
        data = base64.b64decode(f.read())
    keysize_candidates = list()
    for keysize in range(1, 30):
        chunks = chunk_into(data, keysize)
        pairs = itertools.combinations(chunks[:4], 2)
        score = 0
        for a, b in pairs:
            hscore = hamming(a, b)
            logger.debug(hscore)
            score += hscore / keysize
        score /= 4
        keysize_candidates.append((keysize, score))
    keysize_probability = sorted(keysize_candidates, key=lambda x: x[1])
    logger.info("Probable keysizes: {}".format(keysize_probability[:5]))
    for keysize, score in keysize_probability[:3]:
        key_ints = list()
        logger.debug(keysize)
        chunks = chunk_into(data, keysize)
        transposed = zip(*chunks[:-1])
        for c in transposed:
            try:
                _, key_int = english_freq(bytes(c))
                key_ints.append(key_int)
            except TypeError:
                break

        if len(key_ints) == keysize:
            return xor_with_key(data, bytes(key_ints))


def challenge_8():
    with open('8.txt') as f:
        candidates = (base64.b64decode(x) for x in f.readlines())
    best = None
    for candidate in candidates:
        chunks = chunk_into(candidate, 16)
        unique_chunks = len(set(chunks))
        if best is None:
            score = unique_chunks
            best = candidate
        elif unique_chunks < score:
            best = candidate
            score = unique_chunks
        logger.debug(unique_chunks)
    return best, score


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    print(challenge_8())
