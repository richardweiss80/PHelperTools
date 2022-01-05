# hash = "a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611"
# description = "dropped binary, extract the crc32 hashed function names"
# return = "liste of tuples (module, hashedfunction)"

dll_name = {0: "kernel32.dll", 1: "ntdll.dll", 2: "wininet.dll"} # Offset: 0x413c1c

result = []
for x in XrefsTo(0x401210):
    caller = x.frm
    counter = counter + 1
    for h in Heads(caller -4*4, caller):
        mnemonic = print_insn_mnem(h)
        operand_1 = print_operand(h,0)
        operand_2 = print_operand(h,1)
        if (mnemonic == "mov" and operand_1 == "edx"):
            func_hash = operand_2
            verifier_edx = verifier_edx + 1
        elif (mnemonic == "mov" and operand_1 == "ecx"):
            dll_number = int(operand_2)
        elif (mnemonic == "xor" and operand_1 == operand_2 and operand_1 == "ecx"):
            dll_number = 0
    result.append((dll_name[dll_number],func_hash))
print(result)

# result: [('kernel32.dll', '0C1F3B876h'), ('kernel32.dll', '8197004Ch'), ('kernel32.dll', '0BC6B67BFh'), ('wininet.dll', '2B53DA6h'), ('kernel32.dll', '7A3A310h'), ('kernel32.dll', '759903FCh'), ('kernel32.dll', '0A1EFE929h'), ('kernel32.dll', '0CCE95612h'), ('kernel32.dll', '649EB9C1h'), ('kernel32.dll', '0F7C7AE42h'), ('ntdll.dll', '90483FF6h'), ('kernel32.dll', '0E62E824Dh'), ('kernel32.dll', '4F58972Eh'), ('kernel32.dll', '5688CBD8h'), ('kernel32.dll', '5D180413h'), ('kernel32.dll', '3872BEB9h'), ('kernel32.dll', '0A851D916h'), ('kernel32.dll', '4F58972Eh'), ('kernel32.dll', '3872BEB9h'), ('kernel32.dll', '0E62E824Dh'), ('kernel32.dll', '9CE0D4Ah'), ('kernel32.dll', '0FF808C10h'), ('wininet.dll', '0DA16A83Dh'), ('wininet.dll', '16505E0h'), ('wininet.dll', '6CC098F5h'), ('wininet.dll', '0E5191D24h'), ('kernel32.dll', '8436F795h')]
