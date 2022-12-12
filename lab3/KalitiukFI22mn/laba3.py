# -*- coding: utf-8 -*-
"""
Created on Sun Dec  4 15:22:28 2022

@author: Daria
"""

import random
import gmpy2
import math

from PRNGs import Chebyshev_prime
from RSA import RsaGenerateKeyPair, RsaEncrypt, RsaDecrypt
from Rabin import RabinGenerateKeyPair, RabinEncrypt, RabinDecrypt

BITS = 128
n = 7
k = 5
N_0 = 2**BITS

def create_secret():
    return random.randint(1, N_0)

def count_poly_in_point(coefs, point):
    return sum(coefs[j]*point**(j + 1) for j in range(k - 1)) + S

def share_secret():
    p = gmpy2.next_prime(N_0)
    a = [random.randint(1, p) for i in range(k - 1)]
    return [(i, count_poly_in_point(a, i)) for i in range(1, n + 1)]
    
def restoration_secret(parts, k = 5):
    poly_0 = 0
    for i in range(k):
        l_i_1, l_i_2 = 1, 1
        for j in range(k):
            if i != j:
                l_i_1 *= (-parts[0][0] - j)
                l_i_2 *= (i - j)
        poly_0 += (l_i_1//l_i_2)*parts[i][1]
    return poly_0


S = create_secret() 
print('\nSecret:', hex(S))

secret_parts = share_secret()
print('\nShared parts: ', ' '.join([hex(p[1]) for p in secret_parts]))
print('\nResrored secret: ', hex(restoration_secret(secret_parts)))
print('\nAttempt of restoring secret with k < reqiered: ', 
                                  hex(restoration_secret(secret_parts, 4)))


print('\n' + '_'*48 + 'RSA' + '_'*48)

P, Q = Chebyshev_prime(BITS), Chebyshev_prime(BITS)
while P == Q:
    Q = Chebyshev_prime(BITS)
privat_key, public_key = RsaGenerateKeyPair(P, Q)   
print('\nSecret:', hex(S))
secret_parts = share_secret()
cipher_parts = [(p[0], RsaEncrypt(p[1], public_key)) for p in secret_parts]
print('\nShared parts: ', ' '.join(hex(p[1]) for p in cipher_parts))
print('\nReproduced secret: ', hex(restoration_secret([(p[0], RsaDecrypt(p[1], 
                               privat_key, public_key)) for p in cipher_parts])))

print('\n' + '_'*47 + 'Rabin' + '_'*47)
P, Q = Chebyshev_prime(BITS), Chebyshev_prime(BITS)
while P == Q:
    Q = Chebyshev_prime(BITS)
P, Q, b, N = RabinGenerateKeyPair(BITS)   
secret_parts = share_secret()
while any([secret_parts[i][1] <= gmpy2.isqrt(N) for i in range(n)]):
    P, Q, b, N = RabinGenerateKeyPair(BITS)   
l = math.ceil(len(bin(N)[2:])/8)
print('\nSecret:', hex(S))

cipher_parts = [(p[0], RabinEncrypt(p[1], l, b, N)) for p in secret_parts]
print('\nShared parts: ', ' '.join(hex(p[1][0]) for p in cipher_parts))
print('\nReproduced secret: ', hex(restoration_secret([(p[0], 
                               RabinDecrypt(p[1][0], p[1][1], p[1][2], 
                               b, P, Q, N)) for p in cipher_parts])))
