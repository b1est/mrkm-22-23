# -*- coding: utf-8 -*-
"""
Created on Mon Nov 21 11:48:24 2022

@author: Daria
"""

import time
import gmpy2
import random
from APR_CL import APRtest


N = 2**2203 - 1

k = [10, 100, 1000]


def Ferma_test(n, k = 1000):
    for i in range(k):
        a = random.randint(2, n)
        if gmpy2.gcd(n, a) > 1:
            return False
        if not gmpy2.is_fermat_prp(n, a):
            return False
    return True

def Solovay_Strassen_test(n, k = 1000):
    for i in range(k):
        a = random.randint(2, n)
        if not gmpy2.is_euler_prp(n, a):
            return False
    return True    

def Miller_Rabin_test(n, k = 1000):
    for i in range(k):
        a = random.randint(2, n)
        if not gmpy2.is_strong_prp(n, a):
            return False
    return True    

if __name__ == "__main__":
    start_time = time.time()
    print(APRtest(N))
    print(time.time() - start_time, "sec")
    for k_i in k:
        print(f'______k = {k_i}______')
        print('Ferma test')
        start_time = time.time()
        print(Ferma_test(N, k_i))
        print(time.time() - start_time, "sec")
        print('Solovay Strassen test')
        start_time = time.time()
        print(Solovay_Strassen_test(N, k_i))
        print(time.time() - start_time, "sec")
        print('Miller Rabin test')
        start_time = time.time()
        print(Miller_Rabin_test(N, k_i))
        print(time.time() - start_time, "sec")