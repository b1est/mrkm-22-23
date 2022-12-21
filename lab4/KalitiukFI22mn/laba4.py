# -*- coding: utf-8 -*-
"""
Created on Wed Dec 21 13:59:20 2022

@author: Daria
"""

from OpenSSL import crypto

def cert_gen():
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    cert = crypto.X509()
    cert.get_subject().C = 'UA'
    cert.get_subject().ST = 'Kyiv_region'
    cert.get_subject().L = 'Kyiv'
    cert.get_subject().O = 'KPI'
    cert.get_subject().OU = 'FI22mn'
    cert.get_subject().CN = 'Daria'
    cert.get_subject().emailAddress = 'dashamelan2311@gmail.com'
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open('selfsigned.crt', 'wt') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
    #with open('private.key', 'wt') as f:
    #    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))

cert_gen()