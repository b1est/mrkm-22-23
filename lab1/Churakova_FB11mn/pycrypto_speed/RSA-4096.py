from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from os import urandom
import time

key_list = [4096]
for key_length in key_list:
    key = RSA.generate(key_length)
    msg = urandom(32)
    h = SHA256.new(msg)
    obj = pkcs1_15.new(key)
    sign_cycle = 0
    start_s = time.time()
    while time.time() - start_s < 10.0:
        signature = obj.sign(h)
        sign_cycle += 1
    finish_s = time.time()
    print(f"Doing {key_length} bits private rsa's for 10s: {sign_cycle} {key_length} bits private RSA's in {round(finish_s-start_s, 2)}s")
    
    ver_cycle = 0
    start_v = time.time()
    while time.time() - start_v < 10.0:
        obj.verify(h, signature)
        ver_cycle += 1
    finish_v = time.time()

    print(f"Doing {key_length} bits private rsa's for 10s: {ver_cycle} {key_length} bits private RSA's in {round(finish_v-start_v, 2)}s")
    print("")
    print(" \t\tsign \t\tverify \t\tsign/s \t\tverify/s")
    print(f"rsa {key_length} bits \t{round(10/sign_cycle, 6)}s \t{round(10/ver_cycle, 6)}s \t{round(sign_cycle/10,2)} \t\t{round(ver_cycle/10,2)}")
    print("")