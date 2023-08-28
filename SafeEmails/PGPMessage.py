import base64
import zlib

class PGPMessage:
    def __init__(self, sender_key_pair, recipient_key_pair, message):
        self.sender_key_pair = sender_key_pair
        self.recipient_key_pair = recipient_key_pair
        self.message = message
        self.encrypted = False
        self.signed = False
        self.compressed = False
        self.converted = False

    def encrypt(self):
        if self.recipient_key_pair.public_key:
            encrypted_content = self.recipient_key_pair.public_key.encrypt(self.message.encode())
            self.message = base64.b64encode(encrypted_content).decode()
            self.encrypted = True
        else:
            raise ValueError("Recipient's public key is missing.")

    def sign(self):
        if self.sender_key_pair.private_key:
            signature = self.sender_key_pair.private_key.sign(self.message.encode())
            self.message += f"\nSignature: {signature}"
            self.signed = True
        else:
            raise ValueError("Sender's private key is missing.")

    def compress(self):
        self.message = zlib.compress(self.message.encode('utf-8'))
        self.compressed = True

    def convert_to_radix64(self):
        self.message = base64.b64encode(self.message.encode()).decode()
        self.converted = True

    def save_to_file(self, file_path):
        with open(file_path, "w") as file:
            file.write(str(self))

    @classmethod
    def load_from_file(cls, file_path, sender_key_pair, recipient_key_pair):
        with open(file_path, "r") as file:
            content = file.read()
        message = cls(sender_key_pair, recipient_key_pair, "")
        message.parse_content(content)
        return message

    def parse_content(self, content):
        lines = content.split("\n")
        self.message = ""
        self.encrypted = False
        self.signed = False
        self.compressed = False
        self.converted = False

        for line in lines:
            line = line.strip()
            if line.startswith("From:") or line.startswith("To:"):
                continue
            elif line.startswith("Signature:"):
                self.signed = True
            else:
                self.message += line

    def __str__(self):
        return f"From: {self.sender_key_pair.email}\nTo: {self.recipient_key_pair.email}\n\n{self.message}"
