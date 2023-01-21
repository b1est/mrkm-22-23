from source import read, mod_inverse, mul, norm
from point import EllipticCurvePoint as Point
from random import randint
import json
import os

class EllipticCurve:
    def __init__(self, parameters_path: str):
        try:
            parameters = json.loads(read(parameters_path))
        except Exception as e:
            raise e
        
        self.__p = int(parameters['p'], 16)
        self.__m = int(parameters['m'], 16)
        self.__a = int(parameters['a'], 16)
        self.__b = int(parameters['b'], 16)
        self.__order = int(parameters['n'], 16)
        self.__G = self.__randomEllipticCurvePoint()


    @property
    def p(self):
        return self.__p
    

    @property
    def a(self):
        return self.__a
    

    @property
    def b(self):
        return self.__b


    @property
    def order(self):
        return self.__order


    @property
    def G(self):
        return self.__G


    def compress(self, point):
        if point.x == 0:
            return 0

        y = self.__mul(point.y, self.__inverse(point.x))
        t = self.__tr(y)

        mask = (2**self.__m - 1) ^ 1
        return (point.x & mask) | t


    def uncompress(self, c_point):
        if c_point == 0:
            return Point(0, self.__pow(self.__b, self.__pow(2, self.__m - 1)), self.__a, self.__b, self.__p)

        k = (c_point & 1)
        mask = (2**self.__m - 1) ^ 1
        x = c_point & mask

        if self.__tr(x) != self.__a:
            x = x | 1
        
        quad = self.__mul(x, x)
        w = self.__mul(x, quad) ^ self.__mul(self.__a, quad) ^ self.__b
        v = self.__mul(w, self.__inverse(quad))
        res = self.__quadraticEquation(1, v)

        if self.__tr(res["z"]) == k:
            return Point(x, self.__mul(res["z"], x), self.__a, self.__b, self.__p)

        return Point(x, self.__mul(res["z"] ^ 1, x), self.__a, self.__b, self.__p)


    def __mul(self, x1, x2):
        return mul(x1, x2, self.__p)


    def __pow(self, base, exponenta):
        return pow(base, exponenta, self.__p)


    def __inverse(self, x):
        return mod_inverse(x, self.__p)


    def __tr(self, x):
        t = x
        for i in range(self.__m - 1):
            t = mul(t, t, self.__p) ^ x 
        return t


    def __htr(self, x):
        t = x
        for i in range((self.__m - 1) // 2):
            tmp = mul(t, t, self.__p)
            t = mul(tmp, tmp, self.__p) ^ x
        return t

    
    def __quadraticEquation(self, u, w):
        if u == 0:
            return {"k": 1, "z":  self.__pow(w, self.__pow(2, self.__m - 1))}
        if w == 0:
            return {"k": 2, "z": 0}

        tmp = self.__inverse(u)
        v = self.__mul(self.__mul(w, tmp), tmp)

        if self.__tr(v) == 1:
            return {"k": 0, "z": 0}

        t = self.__htr(v)
        return {"k": 2, "z": self.__mul(t, u)}


    def __randomEllipticCurvePoint(self):
        while True:
            u = 0
            z = 0
            while True:
                u = norm(randint(1, 2**self.__m), self.__p)
                w = self.__mul(self.__mul(u, u), u) ^ self.__mul(self.__mul(self.__a, u), u) ^ self.__b

                res = self.__quadraticEquation(u, w)
                if res["k"] > 0:
                    z = res["z"]
                    break
            
            zeroPoint = Point(0, 0, self.__a, self.__b, self.__p)
            resultPoint = Point(u, z, self.__a, self.__b, self.__p)
            if (resultPoint * self.__order) == zeroPoint:
                return Point(u, z, self.__a, self.__b, self.__p)
        
if __name__ == '__main__':
    path = path = os.path.dirname(os.path.abspath(__file__))
    EllipticCurve(f'{path}/elliptic_curve_parameters/elliptic_curve163.json')