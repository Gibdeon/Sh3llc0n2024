import sys
import hashlib
from Crypto.Cipher import AES
from os import urandom

KEY = urandom(16)

def pad(s):
    # Padding for Python3 needs to be in bytes
    pad_len = AES.block_size - len(s) % AES.block_size
    return s + bytes([pad_len] * pad_len)

def aesenc(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = b'\x00' * 16  # Initialization vector for CBC mode
    plaintext = pad(plaintext)  # Plaintext must already be in bytes
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

def convert_to_c_array(byte_data):
    return ', '.join('0x{:02x}'.format(x) for x in byte_data)

def main():
    try:
        with open(sys.argv[1], "rb") as file:  # Open the file in binary mode
            plaintext = file.read()
    except IndexError:
        print("File argument needed! {} <raw payload file>".format(sys.argv[0]))
        sys.exit()
    except IOError as e:
        print("Could not read file:", e)
        sys.exit()

    ciphertext = aesenc(plaintext, KEY)

    key_hex = convert_to_c_array(KEY)
    payload_hex = convert_to_c_array(ciphertext)

    print('#ifndef SAL')
    print('#define SAL')
    print(f'extern unsigned char key[] = {{ {key_hex} }};')
    print(f'extern unsigned char payload[] = {{ {payload_hex} }};')
    print('#endif')

if __name__ == "__main__":
    main()
