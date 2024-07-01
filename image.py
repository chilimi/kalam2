from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Function to encrypt an image
def encrypt_image(image_path, key_path, encrypted_image_path):
    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()

    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)  # Initialization vector

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(image_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(encrypted_image_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + encrypted_data)
      with open(key_path, 'wb') as key_file:
        key_file.write(key)

# Function to decrypt an image
def decrypt_image(encrypted_image_path, key_path, decrypted_image_path):
    with open(encrypted_image_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    with open(key_path, 'rb') as key_file:
        key = key_file.read()

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
  padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(decrypted_image_path, 'wb') as decrypted_file:
        decrypted_file.write(data)

if _name_ == "_main_":
    # Example usage
    encrypt_image('example.png', 'key.bin', 'encrypted_example.bin')
    decrypt_image('encrypted_example.bin', 'key.bin', 'decrypted_example.png')
