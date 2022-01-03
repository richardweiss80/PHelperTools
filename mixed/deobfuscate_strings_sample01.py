# description = "deobfustace strings"
# hash = "a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611"

# import binascii
# used for string_array
# values = "61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 30 31 32 33 34 35 36 37 38 39 30 2E 2F 3D".replace(" ", "")
# print(binascii.unhexlify(values))

def decode(obfuscated):
    deobfuscated : str = ""
    string_array : str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./="
    string_length : int = len(string_array)

    for char in obfuscated:
        position = string_array.find(char)
        if position != -1:
            if position + 13 < string_length:
                value = position + 13
            else:
                value = position - string_length + 13
            res_char = string_array[value]
            deobfuscated = deobfuscated + res_char
        else:
            deobfuscated = "[-] Error: deobfuscation not possible"
    return deobfuscated

obf_strings = ["F5gG8e514pbag5kg",".5ea5/QPY4//", "pe51g5Ceb35ffn", "I9egh1/n//b3rk", "E5fh=5G8e514","Je9g5Ceb35ffz5=bel","I9egh1/n//b3","E514Ceb35ffz5=bel","t5gG8e514pbag5kg","F9m5b6E5fbhe35", "s9a4E5fbhe35n","yb3.E5fbhe35", "yb14E5fbhe35"]
for obf in obf_strings:
    print("%s: %s" % (obf, decode(obf)))

""""
F5gG8e514pbag5kg: SetThreadContext
.5ea5/QPY4//: kernel32.dll
pe51g5Ceb35ffn: CreateProcessA
I9egh1/n//b3rk: VirtualAllocEx
E5fh=5G8e514: ResumeThread
Je9g5Ceb35ffz5=bel: WriteProcessMemory
I9egh1/n//b3: VirtualAlloc
E514Ceb35ffz5=bel: ReadProcessMemory
t5gG8e514pbag5kg: GetThreadContext
F9m5b6E5fbhe35: SizeofResource
s9a4E5fbhe35n: FindResourceA
yb14E5fbhe35: LoadResource
yb3.E5fbhe35: LockResource
"""

# Additional information
# .text:004013B0                         loc_4013B0:                             ; CODE XREF: decrypt+B5↓j
# .text:004013B0 8A 01                                   mov     al, [ecx]
# .text:004013B2 41                                      inc     ecx
# .text:004013B3 84 C0                                   test    al, al
# .text:004013B5 75 F9                                   jnz     short loc_4013B0
# .text:004013B7 2B CF                                   sub     ecx, edi
# .text:004013B9 8D 42 0D                                lea     eax, [edx+0Dh]
# .text:004013BC 3B C1                                   cmp     eax, ecx
# .text:004013BE 7C 07                                   jl      short loc_4013C7
# .text:004013C0 2B D1                                   sub     edx, ecx
# .text:004013C2 83 C2 0D                                add     edx, 0Dh
# .text:004013C5 EB 02                                   jmp     short loc_4013C9

# HEX
# 8A 01 41 84 C0 75 F9 2B  CF 8D 42 0D 3B C1 7C 07
# 2B D1 83 C2 0D EB 02 
