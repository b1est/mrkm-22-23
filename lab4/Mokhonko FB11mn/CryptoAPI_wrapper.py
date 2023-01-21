from DSTU_4145_2002 import DSTU
from source import write, read
import os

class Wrapper:
    def __init__(self, path):
        self.__DSTU = DSTU(path)
        self.__private_key = 0
        self.__public_key = 0


    def generate_private_key(self):
        self.__private_key = self.__DSTU.private_key
        


    def generate_public_key(self):
        if self.__private_key == 0:
            raise Exception()
        if self.__DSTU.private_key != self.__private_key:
            self.__DSTU.set_private_key(self.__private_key)

        self.__public_key = self.__DSTU.public_key


    def export_private_key(self, path):
        if self.__private_key == 0:
            raise Exception()
        self.__private_key = write(path, hex(self.__private_key))


    def export_public_key(self, path):
        if self.__public_key == 0:
            raise Exception()
        self.__public_key = write(path, hex(self.__public_key))


    def import_private_key(self, path):
        self.del_private_key()
        self.del_public_key()
        self.__private_key = int(read(path), 16)


    def import_public_key(self, path):
        self.del_public_key()
        self.__public_key = int(read(path), 16)


    def sign(self, T):
        if self.__private_key == 0:
            raise Exception()
        return self.__DSTU.sign(T, self.__private_key)


    def verify(self, D):
        if self.__public_key == 0:
            raise Exception()
        return self.__DSTU.verify(D, self.__public_key)


    def del_private_key(self):
        del self.__private_key
        self.__private_key = 0

    
    def del_public_key(self):
        del self.__public_key
        self.__public_key = 0

if __name__ == '__main__':
    path = path = os.path.dirname(os.path.abspath(__file__))
    key_path = f'{path}/key'

    st1 = Wrapper(f'{path}/elliptic_curve_parameters/elliptic_curve163.json')
    st1.generate_private_key()
    st1.generate_public_key()
    st1.export_public_key(key_path)
    sig = st1.sign('hello')

    st2 = Wrapper(f'{path}/elliptic_curve_parameters/elliptic_curve163.json')
    st2.import_public_key(key_path)
    res = st2.verify(sig)

    print(res)

