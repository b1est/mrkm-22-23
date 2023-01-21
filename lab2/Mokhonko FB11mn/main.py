from Crypto.PublicKey import RSA, DSA, ECC 

KEY_LEN = 2048
ALGS = {RSA, DSA, ECC}
ALGS_NAMES = {'RSA', 'DSA', 'ECC'}

def write_key(key, alg_name):
    if alg_name == 'ECC':
        with open(f'{alg_name}_private.pem','wt') as file_out:
            file_out.write(key.export_key(format='PEM'))

        with open(f'{alg_name}_public.pem','wt') as file_out:
            file_out.write(key.public_key().export_key(format='PEM'))

    else:
        with open(f'{alg_name}_private.pem', 'wb') as file_out:
            file_out.write(key.export_key(format='PEM'))

        with open(f'{alg_name}_public.pem', 'wb') as file_out:
            file_out.write(key.publickey().export_key(format='PEM'))

def generate_keys_pair():
    for alg, alg_name in zip(ALGS, ALGS_NAMES):
        key = None
        if alg is ECC:
            key = alg.generate(curve='P-256')
        else:
            key = alg.generate(KEY_LEN)
        write_key(key, alg_name)


if __name__ == '__main__': 
    generate_keys_pair()