# description = "resource dump + decrypt"
# hash = "a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611"

import pefile
from Cryptodome.Cipher import ARC4

path = 'C:\\Users\\rwe\\Desktop\\MALWARE\\Zero2Hero\\Practical\\'
input_file = path + "main.bin"
 
def pe_resource_names(pefile_name):
    for rsrc in pefile_name.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            for data in entry.directory.entries:
                yield (entry.id, data)

def decrypt_rc4(key, data):
    return ARC4.new(key).decrypt(data)

def main():
    with open(input_file, "rb") as file:
        data = file.read()
    pe = pefile.PE(data=data)

    resource = pe_resource_names(pe)
    for id, res_data in resource:
        res_content = pe.get_data(res_data.data.struct.OffsetToData, res_data.data.struct.Size)
        rc4_key = res_content[12:27]
        res_encrypted = res_content[28:]
        res_decrypted = decrypt_rc4(rc4_key, res_encrypted)
        if (res_decrypted[:2].decode()) == "MZ":
            print("[+] Decryption ok]")
            output_file = path + str(id) +"_" + str(res_data.id) + ".bin"
            with open(output_file, "wb") as file:
                file.write(res_decrypted)
    return 

if __name__ == "__main__":
    main()
