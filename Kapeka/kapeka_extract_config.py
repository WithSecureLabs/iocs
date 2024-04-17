import pefile
import struct
import re
from Cryptodome.Cipher import AES
import sys
import string
import winreg

def is_file_provided():
    args = sys.argv
    if len(args) > 3:
        print('To extract from registry run: python kapeka_extract_config.py')
        print('To extract from file run: python kapeka_extract_config.py backdoor.exe')
        exit()
    elif len(args) == 2:
        return True
    else:
        return False
def read_file():
    try:
        file_path = sys.argv[1]
        file_data = None
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except:
        print(f'Input file path ({file_path}) could not be read')
        exit()
    return file_data



def parse_config_binary(file_data, pe_file):
    if pe_file.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        egg_32bit = rb'\x68(....)\x68(....)\x8D\x4D\xEC\xE8....\x6A\x20\x68(....)\x8D\x4D\xD8\xE8....\x51\x8D\x55\xD8\x8D\x4D\xEC'
        print('Input file is 32-bit PE, looking for 32-bit pattern...')
        for m in re.finditer(egg_32bit, file_data):
            config_size = struct.unpack('<I',m.group(1))[0]
            config_va = struct.unpack('<I',m.group(2))[0]
            aes_key_va = struct.unpack('<I',m.group(3))[0]
            encrypted_config = pe_file.get_data(config_va - pe_file.OPTIONAL_HEADER.ImageBase, config_size)
            aes_key = pe_file.get_data(aes_key_va - pe_file.OPTIONAL_HEADER.ImageBase, 32)
            config = decrypt_aes(encrypted_config, aes_key).decode('utf-16')
            printable = set(string.printable)
            config = ''.join(filter(lambda x: x in printable, config))
            print(f'Extracted config: {config}')
            return
    elif pe_file.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        egg_64bit = rb'\x41\xB8(....)\x48\x8D\x15(....)\x48\x8D...?\xE8......?\x20\x00\x00\x00\x48\x8D\x15(....)'
        print('Input file is 64-bit PE, looking for 64-bit pattern...')
        for m in re.finditer(egg_64bit, file_data):
            config_size = struct.unpack('<I',m.group(1))[0]
            config_relative_offset = struct.unpack('<I',m.group(2))[0] + 4
            aes_key_relative_offset = struct.unpack('<I',m.group(3))[0] + 4
            config_match_offset = m.start(2)
            config_match_rva = pe_file.get_rva_from_offset(config_match_offset)
            aes_key_match_offset = m.start(3)
            aes_key_match_rva = pe_file.get_rva_from_offset(aes_key_match_offset)
            config_rva = config_match_rva + config_relative_offset
            aes_key_rva = aes_key_match_rva + aes_key_relative_offset
            aes_key_offset = pe.get_offset_from_rva(aes_key_rva)
            aes_key = file_data[aes_key_offset:aes_key_offset+32]
            config_offset = pe.get_offset_from_rva(config_rva)
            encrypted_config = file_data[config_offset:config_offset+config_size]
            config = decrypt_aes(encrypted_config, aes_key).decode('utf-16')
            printable = set(string.printable)
            config = ''.join(filter(lambda x: x in printable, config))
            print(f'Extracted config: {config}')
            return
    print('Config not found...')
    return

def parse_config_registry():
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(registry_key, "MachineGuid")
        winreg.CloseKey(registry_key)
        key = value.encode('utf-16le')[:32]
    except:
        key = 'Azbi3l1xIgcRzTsOHopgrwUdJUMWpOFt'
        print(f'Failed reading MachineGuid... falling back to hardcoded value {key}')
    base_path = r"SOFTWARE\Microsoft\Cryptography\Providers"
    t = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path, 0, winreg.KEY_ALL_ACCESS)
    for i in range(winreg.QueryInfoKey(t)[0]):
        aValue_name = winreg.EnumKey(t, i)
        oKey = winreg.OpenKey(t, aValue_name)
        sValue, sType = winreg.QueryValueEx(oKey, "Seed")
        config = decrypt_aes(sValue, key).decode('utf-16')
        printable = set(string.printable)
        config = ''.join(filter(lambda x: x in printable, config))
        print(f'Extracted config from value "Seed" in HKCU\\{base_path}\\{aValue_name}:\n{config}')


def decrypt_aes(encrypted_data, key):
    iv = b'\x00'*16
    cipher = AES.new(
        key,
     AES.MODE_CBC,
     IV=iv)
    return cipher.decrypt(encrypted_data)

if __name__ == "__main__":
    if is_file_provided():
        try:
            print(f'Extracting config from input file {sys.argv[1]}...')
            file_data = read_file()
            pe = pefile.PE(data=file_data)
            parse_config_binary(file_data, pe)
        except Exception as e:
            print('Error extracting config from file')
            print(e)
    else:
        try:
            print('Extracting config from local registry...')
            parse_config_registry()
        except Exception as e:
            print('Error extracting config from registry')
            print(e)