# Use bindump for extracting the exported functions of the examined DLLs
# e.g. bindump /EXPORTS C:\Windows\System32\kernel32.dll > <filename>
# add the hash func.

# could result in false representation, if the RVA result contains [A-Z]{4,}

import sys
import re
import argparse
import textwrap
from malduck import UInt32


threatactor = ["cycldek", "emotet_new", "FNV_1a", "SF_reflectiveDLL"]

def hash_func(provider, data):
    return globals()[provider](data)


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
    hash = UInt32(0)
    for char in data:
        hash = (hash << 16) + (hash << 6) + ord(char) - hash
    return hex(hash ^ 0x1E5C48DE) # Figure out the correst XOR_Key specific to the sample

def FNV_1a(data):
    # filehash:
    hash = 0
    # ToDo
    return hex(hash)

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
    parser.add_argument('--hashing', required=True, choices = threatactor, help='the hashing routine name')
    parser.add_argument('-o', '--output', dest='output', help='the output file')
    args = parser.parse_args()
    
    dllfile = ""
    regexp = re.compile(r"^\s+\d{1,4}\s+[A-Fa-f0-9]{1,3}\s+([A-Fa-f0-9]{8}\s+\w+|\w+\s+\(.*\))")
    count = 0
    result = {}
    
    with open(args.input, "r", encoding="utf-16") as file_object:
        for line in file_object:
            if "Dump of file" in line:
                dllfile = line.split("\\")[-1].strip()
            if regexp.match(line):
                count = count + 1
                data = line[26:].split(" ")[0].strip()
                result[data] = hash_func(args.hashing, data)

    print(count)

    if  not args.output:
        output_file = "%s_%s_%s_hashed.txt" %(dllfile, hash_func(args.hashing, dllfile), args.hashing)
    else: 
        output_file = args.output  

    with open(output_file , "w", encoding="utf-16") as file_object:
        for key in result.keys():
            file_object.write("%s, %s\n" % (key, result[key]))
