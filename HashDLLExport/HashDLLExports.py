# Use dumpbin for extracting the exported functions of the examined DLLs
# e.g. dumpbin /EXPORTS C:\Windows\System32\kernel32.dll > <filename>
# add the hash func.

# could result in false representation, if the RVA result contains [A-Z]{4,}
# for using a list of strings (seperated by newline) to hash, please use the argument --list

import sys
import re
import argparse
import textwrap
import binascii

threatactor = ["crc32", "cycldek", "emotet_new", "solarwinds_FNV_1a", "SF_reflectiveDLL"]

def hash_func(provider, data):
    return globals()[provider](data)

def crc32(data):
    # filehash: a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611 (decrypted resource content)
    return hex(binascii.crc32(bytes(data, 'utf-8')))

def cycldek(data):
    # filehash: 
    # Cyckdek Windows Functions Hashing Algorithm
    hash = 0
    for char in data:
        hash = (((hash >> 7) & 0xFFFFFFFF) | ((hash << 25) & 0xFFFFFFFF)) + ord(char)
    return hex(hash)

def emotet_new(data):
    # filehash: ba758c64519be23b5abe7991b71cdcece30525f14e225f2fa07bbffdf406e539
    # Used for the new emotet version late 2021
    # For Hashing the basedllname another value is used: 0x326E19FC
    hash = 0
    for char in data:
        hash = ((hash << 16) + (hash << 6) + ord(char) - hash) & 0xFFFFFFFF
    return hex(hash ^ 0x1E5C48DE) # Figure out the correst XOR_Key specific to the sample

def FNV_1a64(data):
    hash = 0xcbf29ce484222325
    fnv_64_prime = 0x100000001b3
    uint64_max = 2 ** 64
    for char in data:
        hash = hash ^ ord(char.lower())
        hash = (hash * fnv_64_prime) % uint64_max
    return hash

def solarwinds_FNV_1a(data):
    # filehash:
    # reference: https://www.mandiant.com/resources/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
    # description: FNV-1A 64 bit XOR 6605813339339102567
    return hex(FNV_1a64(data) ^ 6605813339339102567)

def SF_reflectiveDLL(data):
    #filehash:
    hash = 0
    # ToDo
    return hex(hash)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='HashDLLExport',
        description="Processes dumpbin export list",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            additional information:
                Included Hashing Functions:
                %s
            ''')%(threatactor))
    parser.add_argument('-i', '--input', dest='input', required=True, help='the dumpbin exports output file as input')
    parser.add_argument('--list', help='use a new line seperated list instead of dumbin.exe-export', action='store_true')
    parser.add_argument('--hashing', required=True, choices=threatactor, help='the hashing routine name')
    parser.add_argument('-o', '--output', dest='output', help='the output file')
    args = parser.parse_args()
    
    dllfile = ""
    regexp = re.compile(r"^\s+\d{1,4}\s+[A-Fa-f0-9]{1,3}\s+([A-Fa-f0-9]{8}\s+\w+|\w+\s+\(.*\))")
    count = 0
    result = {}
    
    if not args.list:
        with open(args.input, "r", encoding="utf-16") as file_object:
            for line in file_object:
                if "Dump of file" in line:
                    dllfile = line.split("\\")[-1].strip()
                if regexp.match(line):
                    count = count + 1
                    data = line[26:].split(" ")[0].strip()
                    result[data] = hash_func(args.hashing, data)
    else:
        with open(args.input, "r") as file_object:
            for line in file_object:
                count = count + 1
                result[line] = hash_func(args.hashing, line)

    print(count)

    if  not args.output:
        if not args.list:
            output_file = "%s_%s_%s_hashed.txt" % (dllfile, hash_func(args.hashing, dllfile), args.hashing)
        else:
            output_file = "%s_hashed.txt" % (args.input)
    else: 
        output_file = args.output  

    with open(output_file , "w", encoding="utf-16") as file_object:
        for key in result.keys():
            file_object.write("%s, %s\n" % (key, result[key]))
