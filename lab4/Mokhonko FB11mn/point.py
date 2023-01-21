from source import mul, mod_inverse
from copy import copy

class EllipticCurvePoint:
    def __init__(self, x: int, y: int, a: int, b: int, p: int):
        self.__x = x
        self.__y = y
        self.__a = a
        self.__b = b
        self.__p = p

    
    @property
    def x(self):
        return self.__x


    @property
    def y(self):
        return self.__y


    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return self.__x == other.__x and self.__y == other.__y
        return NotImplemented


    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result


    def __is_inverse(self, other):
        if isinstance(other, EllipticCurvePoint):
            return other.__x == self.__x and other.__y == self.__x ^ self.__y 
        return NotImplemented


    def __mul(self, x1, x2):
        return mul(x1, x2, self.__p)


    def __inverse(self, value):
        return mod_inverse(value, self.__p)


    def __add__(self, other):
        # t = self.__mul(self.y, self.y) ^ self.__mul(self.x, self.y) ^ self.__mul(self.x, self.__mul(self.x, self.x)) ^ self.__mul(self.x, self.x) ^ self.__b
        
        if isinstance(other, EllipticCurvePoint):
            if self.__is_inverse(other):
                return EllipticCurvePoint(0, 0, self.__a, self.__b, self.__p)

            if self.__x == 0 and self.__y == 0:
                return copy(other)
            if other.__x == 0 and other.__y == 0:
                return copy(self)

            x = 0
            y = 0
            if self == other:
                if self.__x == 0:
                    return EllipticCurvePoint(0, 0, self.__a, self.__b, self.__p)

                tmp = self.__mul(self.__x, self.__x)
                x = tmp ^ self.__mul(
                    self.__b, 
                    self.__inverse(tmp)
                )

                y = tmp ^ self.__mul(
                    self.__x ^ self.__mul(self.__y, self.__inverse(self.__x)), 
                    x
                ) ^ x
            else:
                tmp = self.__mul(
                        self.__y ^ other.__y, 
                        self.__inverse(self.__x ^ other.__x)
                    )
                x = self.__mul(tmp, tmp) ^ tmp ^ self.__x ^ other.__x ^ self.__a

                y = self.__mul(
                    tmp,
                    self.__x ^ x
                ) ^ x ^ self.__y            

            return EllipticCurvePoint(x, y, self.__a, self.__b, self.__p)
        return NotImplemented


    def __mul__(self, num: int):
        if isinstance(num, int):
            if num == 0 or self == EllipticCurvePoint(0, 0, self.__a, self.__b, self.__p):
                return EllipticCurvePoint(0, 0, self.__a, self.__b, self.__p)

            tmp =  copy(self)
            if num < 0:
                num = abs(num) 
                tmp.__y ^= tmp.__x
            result = EllipticCurvePoint(0, 0, self.__a, self.__b, self.__p)
            itr = bin(num)[2:][::-1]
            for i in itr:
                if i == '1':
                    result = result + tmp
                tmp = tmp + tmp
            return result
        return NotImplemented

if __name__ == '__main__':
    pass
