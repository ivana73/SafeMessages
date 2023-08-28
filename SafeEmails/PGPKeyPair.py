import datetime
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

import random
from math import gcd

from Crypto.Cipher import CAST
from Crypto.Random import get_random_bytes

import hashlib

from PGPKeyRing import PGPKeyRing


class PGPKeyPair:
    def __init__(self, name, email, algorithm=None, key_size=1024):
        self.name = name
        self.email = email
        self.algorithm = algorithm
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.pem = None
        self.iv_value = None
        self.elgamal_p = None
        self.elgamal_g = None
        self.timestamp = None
        self.hashed_password = None
        self.password = None

    def set_keys(self, public_key, private_key, algorithm, iv_value, email, pem):
        self.algorithm = algorithm
        self.public_key = public_key
        self.private_key = private_key
        self.iv_value = iv_value
        self.email = email
        self.pem = pem

    def set_password(self, password):
        self.password = password
        self.hashed_password = hashlib.sha256(password.encode()).hexdigest()

    def calculate_key_id(self):
        serialized_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_id = int.from_bytes(serialized_key, 'big') & ((1 << 16) - 1)
        return key_id

    def generate_elgamal_key(self, p_size):
        self.elgamal_p = self.generate_large_prime(p_size)
        self.elgamal_g = self.find_generator(self.elgamal_p)

        private_key = random.randint(2, self.elgamal_p - 2)
        public_key = pow(self.elgamal_g, private_key, self.elgamal_p)
        return private_key, public_key

    def generate_large_prime(self, bits):
        while True:
            p = random.getrandbits(bits)
            if self.is_prime(p):
                return p

    def is_prime(self, n, k=5):
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True

    def find_generator(self, p):
        for g in range(2, p):
            if gcd(g, p) == 1:
                return g

    def generate_key_pair(self, password):
        self.timestamp = datetime.datetime.now().timestamp()

        if self.algorithm == "RSA":
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
            )
            self.public_key = self.private_key.public_key()
            self.pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(str.encode(password))
            )
            # Key lock
            self.private_key = None;

        elif self.algorithm == "DSA":
            self.private_key = dsa.generate_private_key(self.key_size)
            self.public_key = self.private_key.public_key()
            self.public_key = self.private_key.public_key()
            self.pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(str.encode(password))
            )
            # Key lock
            self.private_key = None;

        elif self.algorithm == "ElGamal":
            self.private_key, self.public_key = self.generate_elgamal_key(self.key_size)
            # private_key_bytes = self.private_key.to_bytes((self.private_key.bit_length() + 7) // 8, 'big')
            # self.private_key = self.encrypt_private_key(private_key_bytes, self.hashed_password)
        else:
            self.panic()

    def encrypt_private_key(self, private_key_bytes, password):
        self.iv_value = get_random_bytes(8)
        sha1_hash = self.calculate_sha1_hash(password)
        sha1_hash = sha1_hash[-8:]
        cipher = CAST.new(sha1_hash, CAST.MODE_OPENPGP, self.iv_value)
        ciphertext = cipher.encrypt(private_key_bytes)
        return ciphertext

    def store_password_hash(self, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash

    def calculate_sha1_hash(self, password):
        password_bytes = password.encode('utf-8')
        sha1_hash = hashlib.sha1(password_bytes).digest()
        self.hashed_password = self.store_password_hash(password)
        return sha1_hash
    def check_password(self, password, stored_hash):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == stored_hash

    def calculate_sha1_hash_decrypt(self, password):
        password_bytes = password.encode('utf-8')
        sha1_hash = hashlib.sha1(password_bytes).digest()
        return sha1_hash
    def delete_key_pair(self):
        self.private_key = None
        self.public_key = None

    def export_public_key(self, file_path, key_id):
        if self.public_key is not None:
            public_key_bytes = None
            if self.algorithm == "RSA" or self.algorithm == "DSA":
                public_key_bytes = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            elif self.algorithm == "ElGamal":
                public_key_bytes = self.public_key.to_bytes((self.public_key.bit_length() + 7) // 8, 'big')

            pem = public_key_bytes
            os.makedirs(file_path, exist_ok=True)
            with open(file_path + key_id + ".pem", "wb") as public_key_file:
                public_key_file.write(pem)
        else:
            raise ValueError("No public key available.")

    def export_private_key(self, file_path, key_id, password):
        if self.algorithm == 'RSA' or self.algorithm == 'DSA':
            os.makedirs(file_path, exist_ok=True)
            with open(file_path + key_id + ".pem", "wb") as private_key_file:
                private_key_file.write(self.pem)
            return "Private key exported successfully."
        else:
            private_key_bytes = self.private_key.to_bytes((self.private_key.bit_length() + 7) // 8, 'big')
            pem = private_key_bytes
            os.makedirs(file_path, exist_ok=True)
            with open(file_path + key_id + ".pem", "wb") as private_key_file:
                private_key_file.write(pem)
            return "Private key exported successfully."
    def import_private_key(self, file_path, password):
        print(password)
        with open(file_path, "rb") as private_key_file:
            try:
                self.private_key = serialization.load_pem_private_key(
                    private_key_file.read(),
                    password=str.encode(password),
                )
                self.public_key = self.private_key.public_key()
                self.key_size = self.private_key.key_size
                print("success")
            except Exception as e:
                print("Error")
                print(e)
                pass
                # El Gamal here

    def import_public_key(self, file_path):
        with open(file_path, "rb") as public_key_file:
            try:
                pem_data = public_key_file.read()
                self.public_key = serialization.load_pem_public_key(pem_data)
                self.key_size = self.public_key.key_size
                # self.algorithm = self.public_key.
                print("success")
            except Exception as e:
                print("Error")
                print(e)
                pass
                # El Gamal here

    def extract_key_size_algorithm(self, file_path):
        with open(file_path, "rb") as private_key_file:
            pem_data = private_key_file.read()

        private_key = serialization.load_pem_private_key(pem_data, password=None)
        public_key = private_key.public_key()

        key_size = public_key.key_size

        algorithm = private_key.key_type.name

        # print(key_size + " " + algorithm)

        return key_size, algorithm

    def calculate_elgamal_public_key(self, private_key, key_size):
        self.elgamal_p = self.generate_large_prime(key_size)
        self.elgamal_g = self.find_generator(self.elgamal_p)
        elgamal_public_key = pow(self.elgamal_g, private_key, self.elgamal_p)
        return elgamal_public_key

    def panic(self):
        exit()
