import hashlib
import json

from cryptography.hazmat.primitives import serialization

from HashMap import HashMap
from datetime import datetime


class PGPKeyRing:
    def __init__(self):
        self.key_pairs_private = HashMap()
        self.key_pairs_public = HashMap()

    def add_key_pair(self, key_pair):
        if key_pair.algorithm == "RSA" or key_pair.algorithm == "DSA":
            key_id = key_pair.calculate_key_id()
        elif key_pair.algorithm == "ElGamal":
            key_id = key_pair.public_key & ((1 << 64) - 1)  # 64 umesto 16 za sve iznad na kraju da se vrati
        privateKeyDict = {'user name': key_pair.name,
                          'user email': key_pair.email,
                          'key ID': key_id,
                          'iv value': key_pair.iv_value,
                          'pem': key_pair.pem,
                          'public key': key_pair.public_key,
                          'private key': key_pair.private_key,
                          'algorithm': key_pair.algorithm,
                          'key size': key_pair.key_size,
                          'timestamp': key_pair.timestamp}

        self.key_pairs_private.put(key_id, privateKeyDict)
    def add_key_pair_public(self, key_pair):
        if key_pair.algorithm == "RSA" or key_pair.algorithm == "DSA":
            key_id = key_pair.calculate_key_id()
        elif key_pair.algorithm == "ElGamal":
            key_id = key_pair.public_key & ((1 << 64) - 1)  # 64 umesto 16 za sve iznad na kraju da se vrati
        publicKeyDict = {'user name': key_pair.name,
                          'user email': key_pair.email,
                          'key ID': key_id,
                          'iv value': key_pair.iv_value,
                          'pem': key_pair.pem,
                          'public key': key_pair.public_key,
                          'private key': key_pair.private_key,
                          'algorithm': key_pair.algorithm,
                          'key size': key_pair.key_size,
                          'timestamp': key_pair.timestamp}

        self.key_pairs_public.put(key_id, publicKeyDict)
    def remove_key_pair(self, key_pair):
        self.key_pairs.remove(key_pair)

    def get_all_key_pairs(self):
        return self.key_pairs

    def get_key_pair_by_index(self, index):
        map = self.key_pairs_private.get(index)
        if map == []:
            raise IndexError("Invalid key pair index")
        else:
            key_pair = map[0]['key pair']
        return key_pair

    def get_public_pem(key_pair):
        if key_pair['algorithm'] == "RSA" or key_pair['algorithm'] == "DSA":
            pem = key_pair['public key'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode()
        else:
            pass


PGPKeyRing.get_public_pem = staticmethod(PGPKeyRing.get_public_pem)
