from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from settings import Settings
from memory_profiler import profile

@profile
def memProf():
    msg = bytes(Settings.MESSAGE, 'utf-8')
    for i in range(Settings.NUM_TESTS):
        # згенерувати відкритий/закритий ключ
        key = RSA.generate(Settings.CRYPTO_RSA_KEY_LEN, e=17)

        # зашифрувати повідомлення
        encryptor = PKCS1_OAEP.new(key.publickey())
        encrypted = encryptor.encrypt(msg)

        # розшифрувати повідомлення
        decryptor = PKCS1_OAEP.new(key)
        decrypted = decryptor.decrypt(encrypted)


if __name__ == '__main__':
    memProf()