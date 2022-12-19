import cpuinfo
import time
import random
import matplotlib.pyplot as plt
from memory_profiler import profile
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15

@profile
def perform_sha256_tests():
    print ("Performing SHA-256 tests:")
    
    data = []
    hash_time = []
    
    sha256_instance = SHA256.new(b"CopyRights Measures")
    
    for i in range(1000, 10500, 500):
        data_to_hash = random.randbytes(i)
        
        start_time = time.time()
        sha256_hash = sha256_instance.update(data_to_hash)
        end_time = time.time()
        
        time_spent = (end_time - start_time) * 10**3
        
        data.append(i)
        hash_time.append(time_spent)
        
    print ("Array sizes of data tested (in bytes): " + str(data))
    print ("Hash times (ms): " + str(hash_time))
    
    print ("Drawing image...")
    plt.title("SHA-256 Hashing times compared to the Data Length")
    plt.xlabel("Data Length (bytes):")
    plt.ylabel("Time spent (ms):")
    plt.plot(data, hash_time)
    plt.show()

@profile
def perform_aes_256_cbc_tests():
    print ("Performing AES-256-CBC tests:")

    print ("Testing encryption...")

    key = random.randbytes(32)
    iv = random.randbytes(16)

    print ("Generated key: " + str(key))
    print ("Generated IV: " + str(iv))

    aes_instance = AES.new(key, AES.MODE_CBC, iv)
    aes_instance.encrypt(pad(b"CopyRight Measures", AES.block_size))

    data = []
    encrypted_data = []
    encryption_time = []

    for i in range(1000, 10500, 500):
        data_to_encrypt = random.randbytes(i)

        start_time = time.time()
        encrypted = aes_instance.encrypt(pad(data_to_encrypt, AES.block_size))
        end_time = time.time()

        time_spent = (end_time - start_time) * 10**3

        data.append(i)
        encrypted_data.append(encrypted)
        encryption_time.append(time_spent)

    print ("Array sizes of data tested (in bytes): " + str(data))
    print ("Encryption times (ms): " + str(encryption_time))
    
    print ("Drawing image...")
    plt.title("AES-256-CBC Encryption times compared to Data Length")
    plt.xlabel("Data Length (bytes):")
    plt.ylabel("Time spent (ms):")
    plt.plot(data, encryption_time)
    plt.show()

    print ("Testing decryption...")

    aes_instance = AES.new(key, AES.MODE_CBC, iv)
    aes_instance.decrypt(pad(b"CopyRight Measures", AES.block_size))

    decryption_time = []

    for i in encrypted_data:
        start_time = time.time()
        decrypted_data = unpad(aes_instance.decrypt(i), AES.block_size)
        end_time = time.time()

        time_spent = (end_time - start_time)* 10**3

        decryption_time.append(time_spent)

    print ("Decryption times (ms): " + str(decryption_time))

    print ("Drawing image...")
    plt.title("AES-256-CBC Decryption times compared to Data Length")
    plt.xlabel("Data Length (bytes):")
    plt.ylabel("Time spent (ms):")
    plt.plot(data, decryption_time)
    plt.show()

@profile
def perform_rsa_2048_tests():
     print ("Performing RSA-2048 tests:")
     
     print ("Testing encryption...")
     
     rsa_keys = RSA.generate(2048)
     
     private_key = RSA.import_key(rsa_keys.export_key())
     public_key = RSA.import_key(rsa_keys.publickey().export_key())
     
     print ("Private Key: " + str(rsa_keys.export_key()))
     print ("Public Key: " + str(rsa_keys.publickey().export_key()))
     
     rsa_instance = PKCS1_OAEP.new(public_key)
     
     rsa_instance.encrypt(b"CopyRight Measures")
     
     data = []
     encrypted_data = []
     encryption_time = []
     
     for i in range(1, 191):
        data_to_encrypt = random.randbytes(i)

        start_time = time.time()
        encrypted = rsa_instance.encrypt(data_to_encrypt)
        end_time = time.time()

        time_spent = (end_time - start_time) * 10**3

        data.append(i)
        encrypted_data.append(encrypted)
        encryption_time.append(time_spent)
     
     print ("Array sizes of data tested (in bytes): " + str(data))
     print ("Encryption times (ms): " + str(encryption_time))
      
     print ("Drawing image...")
     plt.title("RSA-2048 Encryption times compared to Data Length")
     plt.xlabel("Data Length (bytes):")
     plt.ylabel("Time spent (ms):")
     plt.plot(data, encryption_time)
     plt.show()
     
     print ("Testing decryption...")
     
     rsa_instance = PKCS1_OAEP.new(private_key)
     
     rsa_instance.decrypt(encrypted_data[0])
     
     decryption_time = []
     
     for i in encrypted_data:
        start_time = time.time()
        decrypted = rsa_instance.decrypt(i)
        end_time = time.time()

        time_spent = (end_time - start_time) * 10**3
        
        decryption_time.append(time_spent)
     
     print ("Array sizes of data tested (in bytes): " + str(data))
     print ("Decryption times (ms): " + str(decryption_time))
      
     print ("Drawing image...")
     plt.title("RSA-2048 Decryption times compared to Data Length")
     plt.xlabel("Data Length (bytes):")
     plt.ylabel("Time spent (ms):")
     plt.plot(data, decryption_time)
     plt.show()
     
     print ("Testing signing...")
     
     signature_instance = pkcs1_15.new(private_key)
     sha256_instance = SHA256.new(b"CopyRight Measures")
     
     signature_instance.sign(sha256_instance)
     
     data = []
     signed_messages = []
     singing_time = []
     
     for i in range(1000, 10500, 500):
        message_to_sign = random.randbytes(i)
        
        start_time = time.time()
        sha256_instance.update(message_to_sign)
        signed_message = signature_instance.sign(sha256_instance)
        end_time = time.time()
        
        time_spent = (end_time - start_time) * 10**3
        
        data.append(i)
        signed_messages.append({ "message": message_to_sign, "signature": signed_message })
        singing_time.append(time_spent)
        
     print ("Array sizes of data tested (in bytes): " + str(data))
     print ("Signing times (ms): " + str(singing_time))
     
     print ("Drawing image...")
     plt.title("RSA-2048 Signing times compared to Data Length")
     plt.xlabel("Data Length (bytes):")
     plt.ylabel("Time spent (ms):")
     plt.plot(data, singing_time)
     plt.show()
     
     print ("Testing verification...")
     
     signature_instance = pkcs1_15.new(public_key)
     sha256_instance = SHA256.new(b"CopyRight Measures")
     
     is_valid = []
     verification_time = []
     
     for i in signed_messages:
        message = i["message"]
        signature = i["signature"]
        
        start_time = time.time()
        sha256_instance.update(message)
        valid_signature = sha256_instance
        
        try:
            signature_instance.verify(valid_signature, signature)
            is_valid.append(True)
        except (ValueError, TypeError):
            is_valid.append(False)
            
        end_time = time.time()
        
        time_spent = (end_time - start_time) * 10**3
        
        verification_time.append(time_spent)
        
     print ("Array sizes of data tested (in bytes): " + str(data))
     print ("Is Valid signature (bool): " + str(is_valid))
     print ("Verification times (ms): " + str(verification_time))
      
     print ("Drawing image...")
     plt.title("RSA-2048 Verification times compared to Data Length")
     plt.xlabel("Data Length (bytes):")
     plt.ylabel("Time spent (ms):")
     plt.plot(data, verification_time)
     plt.show()

def main():
    print ("Used libs: cpuinfo, time, random, pyplot, memory_profiler, PyCryptodome")
    print ("CPU where tests will be performed: " + cpuinfo.get_cpu_info()['brand_raw'] + "\n")
    
    # sha-256
    perform_sha256_tests()
    #

    # aes-256-cbc
    perform_aes_256_cbc_tests()
    #
    
    # rsa-2048
    perform_rsa_2048_tests()
    #

if __name__ == '__main__':
    main()