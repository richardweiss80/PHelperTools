# hash = "a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611"
# description = "deobfuscation of loaded functions and modules"
# only a quick code snippet for demonstration, how to get the hashed strings and put comments in IDA to the call functions.
# used this time to put the cursor on the deobfuscation function. The pos value can also be hardcoded or the target_func (0x00401300)

idaapi.msg_clear()

def deobf_str(obfuscated):
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

pos = here()
target_func = get_operand_value(pos, 0)
counter_xrefto = 0

result = []

for xref in XrefsTo(target_func):
    counter_xrefto = counter_xrefto + 1
    caller = xref.frm
    for head in Heads(caller - 4*4, caller):
        if print_insn_mnem(head) == "mov" and print_operand(head, 0) == "ecx":
            offset_mov = head
            #string_ptr = print_operand(head, 1)
            string_ptr_offset = get_operand_value(head, 1)
    string_ptr_content = (get_strlit_contents(string_ptr_offset, -1, get_str_type(string_ptr_offset))).decode("utf-8")
    deobf = deobf_str(string_ptr_content)
    print(f"{hex(caller)}: {hex(offset_mov)} - {hex(string_ptr_offset)} - {string_ptr_content} - {deobf}")

    # comment and rename 2nd operand
    set_cmt(caller, deobf, 0)
    # set_name(string_ptr_offset, f"str_{deobf}")
    
    
# output:
# 0x401065: 0x401060 - 0x414894 - .5ea5/QPY4// - kernel32.dll
# 0x40106f: 0x40106a - 0x4148a4 - pe51g5Ceb35ffn - CreateProcessA
# 0x4010bf: 0x4010ba - 0x4148e8 - I9egh1/n//b3 - VirtualAlloc
# 0x4010f5: 0x4010ba - 0x4148e8 - I9egh1/n//b3 - VirtualAlloc
# 0x401128: 0x401123 - 0x4148f8 - E514Ceb35ffz5=bel - ReadProcessMemory
# 0x401147: 0x401140 - 0x4148d4 - Je9g5Ceb35ffz5=bel - WriteProcessMemory
# 0x401191: 0x40118c - 0x4148b4 - I9egh1/n//b3rk - VirtualAllocEx
# 0x40126c: 0x401267 - 0x414880 - F5gG8e514pbag5kg - SetThreadContext
# 0x40128d: 0x401286 - 0x4148c4 - E5fh=5G8e514 - ResumeThread
# 0x40141b: 0x401416 - 0x414920 - .5ea5/QPY4// - kernel32.dll
# 0x401425: 0x401420 - 0x414940 - s9a4E5fbhe35n - FindResourceA
# 0x40144c: 0x401445 - 0x414970 - yb14E5fbhe35 - LoadResource
# 0x401467: 0x401460 - 0x414930 - F9m5b6E5fbhe35 - SizeofResource
# 0x401486: 0x40147f - 0x414960 - yb3.E5fbhe35 - LockResource
# 0x4014f5: 0x4014e8 - 0x414950 - I9egh1/n//b3 - VirtualAlloc
