from elliptic_curve import EllipticCurve as EC
from point import EllipticCurvePoint as Point
import hashlib
import random
import os
from source import norm, mul

class DSTU:
    def __init__(self, path):
        self.__EC = EC(path)
        self.__LOrder = len(bin(self.__EC.order)[2:])
        self.__H = hashlib.sha256
        self.__LD = 1024
        self.__Q = None
        self.__compressedQ = 0
        self.__d = 0

    def __gen_d(self):
        self.__d = random.randint(1, self.__EC.order - 1)

    
    def __calc_Q(self):
        if self.__d == 0:
            return False
        self.__Q = self.__EC.G * (-self.__d)
        return True
        

    @property
    def private_key(self):
        if self.__d == 0:
            self.__gen_d()
        return self.__d
    
    
    @property
    def public_key(self):
        if self.__Q == None:
            if not self.__calc_Q(): 
                raise Exception("Public key and private key is missing")
        if self.__compressedQ == 0:
            self.__compressedQ = self.__EC.compress(self.__Q)
        return self.__compressedQ


    def set_private_key(self, key):
        self.__d = key


    def set_public_key(self, key):
        self.__compressedQ = key


    def __norm_hash(self, num):
        bnum = bin(num)[2:]
        len_ = len(bnum)
        if (len_ < self.__LOrder):
            return num
        
        return int(bnum[len_ - self.__LOrder:], 2)

    
    def __norm(self, num):
        return norm(num, self.__EC.p)


    def sign(self, T: str, d: int):
        if d == None:
            raise Exception("Private key is missing")

        hash = int(self.__H(bytes(T, 'utf-8')).hexdigest(), 16)
        h = self.__norm_hash(hash)
        if h == 0:
            h = 1

        R = Point(0, 0, self.__EC.a, self.__EC.b, self.__EC.order)
        s = 0
        while R.x == 0 or s == 0:
            e = random.randint(1, self.__EC.order - 1)
            R = self.__EC.G * e
            if R.x == 0:
                continue

            r = mul(h, R.x, self.__EC.p)
            if r == 0:
                continue

            s = (e + d * r) % self.__EC.order

        D = ['0' * (self.__LD // 8 - len(hex(s)[2:])) + hex(s)[2:], '0' * (self.__LD // 8 - len(hex(r)[2:])) + hex(r)[2:]]        
        return [''.join([T, *D]), self.__EC.compress(self.__EC.G)]


    def verify(self, sign_, c_public_key):
        sign, G = sign_
        G = self.__EC.uncompress(G)
        public_key = self.__EC.uncompress(c_public_key)

        Lt = len(sign) - (self.__LD // 4)
        T = sign[:Lt]
        sign = sign[Lt:]

        s = int(sign[:self.__LD // 8], 16)
        r = int(sign[self.__LD // 8:], 16)

        hash = int(self.__H(bytes(T, 'utf-8')).hexdigest(), 16)
        h = self.__norm_hash(hash)
        if h == 0:
            h = 1

        R = G * s + public_key * r
        y = mul(R.x, h, self.__EC.p)
        ir = hex(self.__norm(y))
        return ir == hex(r)
 

if __name__ == '__main__':
    path = path = os.path.dirname(os.path.abspath(__file__))
    st = DSTU(f'{path}/elliptic_curve_parameters/elliptic_curve163.json')
    
    sign = st.sign('hello', st.private_key)
    res = st.verify(sign, st.public_key)
    print(res)

    st2 = DSTU(f'{path}/elliptic_curve_parameters/elliptic_curve163.json')
    res = st2.verify(sign, st.public_key)

    print(res)