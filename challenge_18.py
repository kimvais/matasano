import base64
import logging

import aes
from tests import KEY


CIPHERTEXT = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')

__author__ = 'kimvais'

logger = logging.getLogger('Challenge 18')


def main():
    c = aes.CTR(KEY)
    return c.encrypt(CIPHERTEXT)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s.%(funcName)s:[%(lineno)s]: %(message)s')
    logger.info(main())