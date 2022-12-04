# -*- coding: utf-8 -*-
"""
Created on Sun Dec  4 15:13:54 2022

@author: Daria
"""
import gmpy2
import random


def RsaGenerateKeyPair(p, q):
    n = gmpy2.mul(p, q)
    oiler = gmpy2.mul(p - 1, q - 1)
    e = random.randint(2, oiler - 1)
    while gmpy2.gcd(e, oiler) > 1:
        e = random.randint(2, oiler - 1)
    d = gmpy2.invert(e, oiler)
    return d, (e, n)


def RsaEncrypt(message, public_key):
    return gmpy2.powmod(message, public_key[0], public_key[1])


def RsaDecrypt(cypher_message, d, public_key):
    return gmpy2.powmod(cypher_message, d, public_key[1])