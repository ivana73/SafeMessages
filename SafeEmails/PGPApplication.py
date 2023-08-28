from PGPKeyPair import PGPKeyPair
from PGPKeyRing import PGPKeyRing
from PGPMessage import PGPMessage


class PGPApplication:
    def __init__(self):
        self.key_ring = PGPKeyRing()

    def generate_key_pair(self, name, email, algorithm, key_size):
        key_pair = PGPKeyPair(name, email, algorithm, key_size)
        key_pair.generate_key_pair()
        self.key_ring.add_key_pair(key_pair)
        return key_pair

    def encrypt_message(self, sender_key_pair_index, recipient_key_pair_index, message):
        sender_key_pair = self.key_ring.get_key_pair_by_index(sender_key_pair_index)
        recipient_key_pair = self.key_ring.get_key_pair_by_index(recipient_key_pair_index)
        pgp_message = PGPMessage(sender_key_pair, recipient_key_pair, message)
        pgp_message.encrypt()
        return pgp_message

    def sign_message(self, sender_key_pair_index, message):
        sender_key_pair = self.key_ring.get_key_pair_by_index(sender_key_pair_index)
        pgp_message = PGPMessage(sender_key_pair, None, message)
        pgp_message.sign()
        return pgp_message

    def compress_message(self, message):
        pgp_message = PGPMessage(None, None, message)
        pgp_message.compress()
        return pgp_message

    def convert_to_radix64(self, message):
        pgp_message = PGPMessage(None, None, message)
        pgp_message.convert_to_radix64()
        return pgp_message

    def run(self):
        print("Welcome to the PGP application!")
        while True:
            print("\nPlease select an option:")
            print("1. Generate key pair")
            print("2. Encrypt message")
            print("3. Sign message")
            print("4. Compress message")
            print("5. Convert message to radix-64")
            print("0. Exit")

            choice = input("Enter your choice: ")

            if choice == "1":
                name = input("Enter the name: ")
                email = input("Enter the email: ")
                algorithm = input("Enter the algorithm (RSA, DSA, ElGamal): ")
                key_size = int(input("Enter the key size: "))
                self.generate_key_pair(name, email, algorithm, key_size)
                print("Key pair generated successfully!")

            elif choice == "2":
                sender_index = int(input("Enter the index of the sender key pair: "))
                recipient_index = int(input("Enter the index of the recipient key pair: "))
                message = input("Enter the message: ")
                encrypted_message = self.encrypt_message(sender_index, recipient_index, message)
                print("Message encrypted successfully!")
                print("Encrypted Message:")
                print(encrypted_message)

            elif choice == "3":
                sender_index = int(input("Enter the index of the sender key pair: "))
                message = input("Enter the message: ")
                signed_message = self.sign_message(sender_index, message)
                print("Message signed successfully!")
                print("Signed Message:")
                print(signed_message)

            elif choice == "4":
                message = input("Enter the message: ")
                compressed_message = self.compress_message(message)
                print("Message compressed successfully!")
                print("Compressed Message:")
                print(compressed_message)

            elif choice == "5":
                message = input("Enter the message: ")
                radix64_message = self.convert_to_radix64(message)
                print("Message converted to radix-64 successfully!")
                print("Radix-64 Message:")
                print(radix64_message)

            elif choice == "0":
                print("Exiting the PGP application...")
                break

            else:
                print("Invalid choice. Please try again.")