from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time
from settings import Settings

msg = bytes(Settings.MESSAGE, 'utf-8')

bgn = time.time()
for i in range(Settings.NUM_TESTS):
    # згенерувати відкритий/закритий ключ
    key = RSA.generate(Settings.CRYPTO_RSA_KEY_LEN, e=17)
print(f'private/open key: {time.time() - bgn}')

bgn = time.time()
for i in range(Settings.NUM_TESTS):
    # зашифрувати повідомлення
    encryptor = PKCS1_OAEP.new(key.publickey())
    encrypted = encryptor.encrypt(msg)
print(f'cipher text: {time.time() - bgn}')

bgn = time.time()
for i in range(Settings.NUM_TESTS):
    # розшифрувати повідомлення
    decryptor = PKCS1_OAEP.new(key)
    decrypted = decryptor.decrypt(encrypted)
print(f'open text: {time.time() - bgn}')
