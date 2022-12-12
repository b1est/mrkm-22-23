# -*- coding: utf-8 -*-
"""
Created on Sun Dec  4 15:25:47 2022

@author: Daria
"""

from PRNGs import Chebyshev_prime
from primality_tests import Miller_Rabin_test
import gmpy2
import random

def RabinGenerateKeyPair(size):
    p = Chebyshev_prime(size)
    while (p - 3)%4 != 0 or not Miller_Rabin_test(p):
        p = Chebyshev_prime(size)
    q = Chebyshev_prime(size)
    while (q - 3)%4 != 0 or not Miller_Rabin_test(q):
        q = Chebyshev_prime(size)
    n = gmpy2.mul(p, q)
    b = random.randint(1, n - 1)
    return p, q, b, n

def square_root(y, p, q, n):
    s1 = gmpy2.powmod(y, (p + 1)//4, p)
    s2 = gmpy2.powmod(y, (q + 1)//4, q)
    u, v = gmpy2.gcdext(p, q)[1:]
    return ((u*p*s2 + v*q*s1)%n, (u*p*s2 - v*q*s1)%n, 
         (-u*p*s2 + v*q*s1)%n, (-u*p*s2 - v*q*s1)%n)

def Format(m, l):
    r = random.getrandbits(64)
    return 255*(1 << (8*(l - 2))) + m*(1 << 64) +  r

def  Iverson_bracket(x, b, n):
    return 1 if gmpy2.jacobi(x + b*gmpy2.invert(2, n), n) == 1 else 0


def RabinEncrypt(m, l, b, n):
    x = Format(m, l)
    y = x*(x + b)%n
    c1 = int(((x + b*gmpy2.invert(2, n))%n)%2)
    c2 = Iverson_bracket(x, b, n)
    return y, c1, c2


def RabinDecrypt(y, c1, c2, b, p, q, n):
    for sq in square_root((y + (b*gmpy2.invert(2, n))**2)%n, p, q, n):
        x = (-b*gmpy2.invert(2, n) + sq)%n
        if int(((x + b*gmpy2.invert(2, n))%n)%2) == c1:
            if Iverson_bracket(x, b, n) == c2:
                x =  bin(x)[10:-64]
                while x[0] == '0':
                    x = x[1:]
                return int(x, 2)