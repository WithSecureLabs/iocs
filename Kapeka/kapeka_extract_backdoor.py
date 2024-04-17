import pefile
import struct
import re
from Cryptodome.Cipher import AES
from ctypes import *
from ctypes.wintypes import DWORD, LPVOID , UINT, BOOL, BYTE, LPCSTR
import sys
from pathlib import Path

def read_file():
    args = sys.argv
    if len(args) < 2 or len(args) > 3:
        print('Usage: python kapeka_extract_backdoor.py dropper.exe')
        exit()
    try:
        file_path = sys.argv[1]
        file_data = None
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except Exception as e:
        print(f'Input file path ({file_path}) could not be read')
        print(e)
        exit()
    return file_data, file_path

def parse_password(file_data, pe_file):
    egg = rb'\x66\x83\x3D(....)\x00\xB8(....)'
    for m in re.finditer(egg, file_data):
        if m.group(1) != m.group(2):
            print('Password not found in binary')
            exit()
        pwd_va = struct.unpack('<I', m.group(1))[0]
        pwd = pe_file.get_data(pwd_va - pe_file.OPTIONAL_HEADER.ImageBase,16)
    return pwd

def parse_resources(pe_file):
     resources = []
     for rsrc in pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                id = entry.id
                resources.append((offset,size,id))
     return resources

def decrypt_aes(encrypted_data, key):
    iv = b'\x00'*16
    cipher = AES.new(
        key,
     AES.MODE_CBC,
     IV=iv)
    return cipher.decrypt(encrypted_data)

def process_resources(resources, password, file_path):
     for offset, size, entry_id in resources:
        data = pe.get_memory_mapped_image()[offset:offset+size]
        decryption_key = aes_generate_key_winapi(password)
        decrypted = decrypt_aes(data, decryption_key)
        file_name = Path(file_path).stem + f'_decrypted_resource_{entry_id}.dmp'
        with open(file_name,'wb') as w:
            print(f'Saving decrypted resource {entry_id} into {file_name}')
            w.write(decrypted)

def aes_generate_key_winapi(password):
    CryptAcquireContextW = windll.advapi32.CryptAcquireContextW
    CryptCreateHash = windll.advapi32.CryptCreateHash
    CryptHashData = windll.advapi32.CryptHashData
    CryptDeriveKey = windll.advapi32.CryptDeriveKey
    CryptExportKey = windll.advapi32.CryptExportKey
    hProv = c_void_p()
    CryptAcquireContextW(byref(hProv), 0, 0, 0x0018, 0xF0000000)
    hHash = c_void_p()
    CryptCreateHash(hProv, 0x00008003, 0, 0, byref(hHash))
    password=password.replace(b'\x00',b'').decode('utf-8')
    CryptHashData(hHash, password, 2*len(password), 0)
    hKey = c_void_p()
    CryptDeriveKey(hProv, 0x6610, hHash, 1, byref(hKey))
    pbData = create_string_buffer(64) 
    pdwDataLen = DWORD(64)
    CryptExportKey(hKey, 0, 0x8, 0, byref(pbData), byref(pdwDataLen))
    return pbData.raw[pdwDataLen.value-32:pdwDataLen.value]


if __name__ == "__main__":
    file_data, file_path = read_file()
    pe = pefile.PE(data=file_data)
    try:
        password = parse_password(file_data, pe)
        resources = parse_resources(pe)
        process_resources(resources, password, file_path)
    except Exception as e:
        print('Error processing file...')
        print(e)
        exit()
