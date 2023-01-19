# -*- coding: utf-8 -*-
"""
Created on Fri Jan 13 19:18:25 2023

@author: User
"""

import galois

import numpy as np
import math
import Cryptodome as Crypto
from Cryptodome.Hash import SHA512

def generate_random_element(GF):
    return GF.Random()

def check_point(GF, A, B, m, P):
    if ((P[1]*P[1] + P[0]*P[1])==(P[0]**3 + A*(P[0]**2) + B)):
        return True
    return False

param = 163
m = param
GF = galois.GF(2**param, repr = "poly")
T = 1337

def htr(x):
    t = x
    for i in range(int((m-1)/2)):
        t = (t**4) + x
    return t

def tr(x):
    t = x
    for i in range((m-1)):
        t = (t**2) + x
    return t

def check_square(GF, m, u, w):
    if (u == 0):
        return 1, w ** (2**(m-1))
    if (w == 0):
        return 2, GF(0)
    
    v = w*(u ** (-2))
    if (tr(v) == 1):
        return 0, GF(0)
    t = htr(v)
    return 2, t*u

def random_point(GF, A, B, m):
    while True:
        u = generate_random_element(GF)
        w = u**3 + A*(u**2) + B
        temp, z = check_square(GF, m, u, w)
        if(temp != 0):
            break
    return((u, z)) 

def byte_to_bit(data):
    data_bit = ""
    for i in data:
        data_bit += '{0:08b}'.format(i)
    return (data_bit)

def signature_to_pair(Ld, D):
    r_bit = ""
    s_bit = ""
    O = "0"*Ld
    l = int(Ld/2)
    r_bit += D[l:]
    s_bit += D[:l]
    r = int(r_bit[:r_bit.rfind('1')+1], 2)
    s = int(s_bit[:s_bit.rfind('1')+1], 2)
    return r, s

def hash_to_GF(GF, m, hash_string):
    bitstring = byte_to_bit(hash_string)[:m]
    
    return(GF(int(bitstring, 2)))

def pair_to_signature(Ld, r, s):
    R = ""
    S = ""
    O = "0"*Ld
    l = int(Ld/2)
    R += bin(r)[2:]
    R += O[:(l - len(R))]
    S += bin(s)[2:]
    S += O[:(l - len(S))]
    D = S + R
    return D

def SHA3_512(input_byte_string):
    hash_f = SHA512.new(truncate="256")
    hash_f.update(input_byte_string)
    output_byte_string = hash_f.digest()
    return output_byte_string

def eleptic_curve_addition(P, Q, A, B):
    if (P==Q):
        if(P[0] == GF(0)):
            return ((GF(0),GF(0)))
        t = P[1] * (P[0]**(-1)) + P[0]
        Rx = t*t + t + A
        Ry = P[0]*P[0] + t*Rx + Rx
    elif ((P[0]==Q[0]) and (P[1] == (Q[1] + Q[0]))):
        return ((GF(0),GF(0)))    
    else:
        Rx = ((P[1] + Q[1])*((P[0] + Q[0])**(-1)))**2 + (P[1] + Q[1])*((P[0] + Q[0])**(-1)) + P[0] + Q[0] + A
        Ry = ((P[1] + Q[1])*((P[0] + Q[0])**(-1)))*(P[0] + Rx) + Rx + P[1]
    R = (Rx, Ry)
    if (check_point(GF, A, B, m, R)==False):
        return ((GF(0),GF(0)))    
    return R

def eleptic_curve_multiplication(P, n, A, B):
    k = bin(n)[2:]
    Q = P
    if (Q == (GF(0), GF(0))):
        return Q
    #k = k[::-1]
    k = k[1:]
    for i in k:
        Q = eleptic_curve_addition(Q, Q, A, B)
        #if (Q == (GF(0), GF(0))):
            #return Q
        if(i == '1'):
            Q = eleptic_curve_addition(Q, P, A, B)
            #if (Q == (GF(0), GF(0))):
                #return Q
    return Q


class curve():
    def __init__(self, param):
        if (param == 163):
            self.curve_163()
        elif (param == 179):
            self.curve_179()
        else:
            print("error: curve was not created")
        
        GF = self.GF
        
        self.sk, self.Q = self.keygen()
        #if (param == 163):
        #    self.Q = (GF(9367128107881921444512701623009555219779675840028),
        #              GF(3024508227664414051163668185519433797426792498520) )
        while True:
            Fe, e = self.pre_signature()
            self.D, self.L = self.signature(self.iH, 512, e, Fe, 1337)
            if (self.check_signature(self.D, self.L, self.Q)==True):
                break
            self.sk, self.Q = self.keygen()
        
            
    def htr(self, x):
        t = x
        for i in range(int((self.m-1)/2)):
            t = (t**4) + x
        return t
    
    def tr(self, x):
        t = x
        for i in range((self.m-1)):
            t = (t**2) + x
        return t
    
    def keygen(self):
        sk = Crypto.Random.random.randint(1, self.n)
        npk = eleptic_curve_multiplication(self.P, sk, self.A, self.B)
        pk = (npk[0], npk[1]+npk[0])
        return sk, pk
    
    def check_private_key(self):
        Q_ = eleptic_curve_multiplication(self.P, self.sk, self.A, self.B)
        pk = (Q_[0], Q_[1]+Q_[0])
        if (pk == self.Q):
            return True
        return False
    
    def check_public_key(self, Q):  #check
        if (Q == (self.GF(0), self.GF(0))):
            return False
        if (check_point(self.GF, self.A, self.B, self.m, Q) == False):
            return False
        check = eleptic_curve_multiplication(Q, self.n, self.A, self.B)
        if (check == (self.GF(0), self.GF(0))):
            return True
        return False
    
    def pre_signature(self):
        while True:
            e = Crypto.Random.random.randint(0, self.n)
            R = eleptic_curve_multiplication(self.P, e, self.A, self.B)
            if (R[0] != self.GF(0)):
                break
        return R[0], e
    
    def base_point(self):
        while True:
            P = random_point(self.GF, self.A, self.B, self.m)
            R = eleptic_curve_multiplication(self.P, self.n, self.A, self.B)
            if (R == (self.GF(0), self.GF(0))):
                break
        return P
    
    def signature(self, iH, Ld, e, Fe, T):
        if (Ld%16 != 0):
            return "Error"
        if (Ld < 2*len(bin(self.n)[2:])):
            return "Error"
        H_t = self.hash_f(iH, bytes(T))
        h = hash_to_GF(self.GF, self.m, H_t)
        y = h*Fe
        r = int(y) % self.n
        s = (e+ self.sk*r)%self.n
        D = pair_to_signature(Ld, r, s)
        return ((iH, T, D), (len(bin(iH)[2:])+len(bin(T)[2:])+Ld))
    
    def check_signature(self, signature, L, Q):
        if (signature[0] != self.iH): 
            return "Error"
        if (self.check_public_key(Q) == False):
            return "Error"
        if ((L - len(signature[2]) - len(bin(self.iH)[2:])) <= 0):
            return "Error"
        r, s = signature_to_pair(len(signature[2]), signature[2])
        R = eleptic_curve_addition(eleptic_curve_multiplication(self.P, s, self.A, self.B), eleptic_curve_multiplication(Q, r, self.A, self.B), self.A, self.B)
        H_t = self.hash_f(signature[0], bytes(signature[1]))
        h = hash_to_GF(self.GF, self.m, H_t)
        r_ = int(h*R[0])%(self.n)
        if(r == r_):
            return True
        else:
            return "Error"
        
    def hash_f(self, iH, input_byte_string):
        if (iH == 1):
            return SHA3_512(input_byte_string)
        else:
            print("Error: wrong hash ID")
            return "Error"
    
    def curve_163(self):
        self.GF = galois.GF(2**163, repr = "poly")
        self.A = self.GF(1)
        self.B = self.GF(0x5FF6108462A2DC8210AB403925E638A19C1455D21)
        self.n = 0x400000000000000000002BEC12BE2262D39BCF14D
        self.m = 163
        self.P = (self.GF(0x2E2F85F5DD74CE983A5C4237229DAF8A3F35823BE), self.GF(0x3826F008A8C51D7B95284D9D03FF0E00CE2CD723A))
        self.iH = 1
        
    def curve_179(self):
        self.GF = galois.GF(2**179, repr = "poly")
        self.A = self.GF(1)
        self.B = self.GF(0x4A6E0856526436F2F88DD07A341E32D04184572BEB710)
        self.n = 0x3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF
        self.m = 179
        self.P = self.base_point()
        self.iH = 1
        
    def create_signature(self, T):
        while True:
            Fe, e = self.pre_signature()
            D, L = self.signature(self.iH, 512, e, Fe, 1337)
            if (self.check_signature(self.D, self.L, self.Q)==True):
                break
        return D, L