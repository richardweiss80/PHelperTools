# Use bindump for extracting the exported functions of the examined DLLs
# e.g. bindump /EXPORTS C:\Windows\System32\kernel32.dll > <filename>
# add the hash func.

# could result in false representation, if the RVA result contains [A-Z]{4,}

import sys
import re

threatactor = "cycldek"

def hash_func(data):
    # Cyckdek Windows Functions Hashing Algorithm
    hash = 0
    for char in data:
        hash = (((hash >> 7) & 0xFFFFFFFF) | ((hash << 25) & 0xFFFFFFFF)) + ord(char)
    result[data] = hex(hash)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: <toolname> <filename>")

    regexp = re.compile(r"^\s+\d{1,4}\s+[A-Fa-f0-9]{1,3}\s+([A-Fa-f0-9]{8}\s+\w+|\w+\s+\(.*\))")
    count = 0
    result = {}
    
    with open(sys.argv[1], "r", encoding="utf-16") as file_object:
        for line in file_object:
            if regexp.match(line):
                count = count + 1
                hash_func((re.findall(r'[a-zA-Z_]{4,}', line))[0])

    print(count)
    with open("%s_%s_hashed" %(sys.argv[1], threatactor) , "w", encoding="utf-16") as file_object:
        for key in result.keys():
            file_object.write("%s, %s\n" % (key, result[key]))
