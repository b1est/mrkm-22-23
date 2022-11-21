# -*- coding: utf-8 -*-
"""
Created on Mon Nov 21 15:11:27 2022

@author: Daria
"""

from primality_tests import Miller_Rabin_test
from PRNGs import LehmerHigh, Chebyshev_prime, A_L, M_L, C_L



if __name__ == '__main__':
    N = 1024
    print('Generate pseudo random sequence:')
    print(LehmerHigh(A_L, M_L, C_L, N//8))
    print('Generate prime number:')
    prime = Chebyshev_prime(N)
    print(prime)
    print("Check it's primality:")
    print(Miller_Rabin_test(prime))
    