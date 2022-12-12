from Crypto.Cipher import AES
import cProfile
from os import urandom
import time

key_list = [16]
for key in key_list:
    secret_key = urandom(key)
    iv = urandom(16)
    byte_list = [16, 64, 256, 1024, 8192, 16384]
    type_str = "type \t\t"
    bytes_per_sec = f"aes-{key*8} cbc\t"
    for byte in byte_list:
        msg = urandom(byte)
        start = time.time()
        full_cycle = 0
        obj = AES.new(secret_key, AES.MODE_CBC, iv)
        while time.time() - start < 3.0:
            encrypted_msg = obj.encrypt(msg)
            full_cycle += 1
        finish = time.time()
        print(f"Doing aes-{key*8} cbc for 3s on {byte} size blocks: {full_cycle} aes-{key*8} cbc's in {round(finish-start, 2)}'s")
        type_str += f"\t {byte} bytes"
        bytes_per_sec += f"\t {round(((full_cycle/3)*byte)/1000, 2)}k"
    print("The 'numbers' are in 1000s of bytes per second processed.")
    print(type_str)
    print(bytes_per_sec)
    print("")