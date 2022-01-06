# hash = "a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611"
# description = "dropped binary, extract the crc32 hashed function names"
# return = "liste of tuples (module, hashedfunction)"
# only a quick code snippet for demonstration, how to get the hashed strings and put comments in IDA to the call functions.

idaapi.msg_clear()

path = "C:\\Users\\rwe\\Desktop\\Development\\PHelperTools\\"
dll_name = {0: "kernel32.dll", 1: "ntdll.dll", 2: "wininet.dll"} # Offset: 0x413c1c
kernel32_hashed = path + "kernel32.dll_0x6ae69f02_crc32_hashed.txt"
wininet_hashed = path + "wininet.dll_0xc7f465f7_crc32_hashed.txt"
ntdll_hashed = path + "ntdll.dll_0x84c05e40_crc32_hashed.txt"

counter = 0
result = []
for x in XrefsTo(0x401210):
    counter = counter + 1
    caller = x.frm
    for h in Heads(caller -4*4, caller):
        mnemonic = print_insn_mnem(h)
        operand_1 = print_operand(h,0)
        operand_2 = print_operand(h,1)
        if (mnemonic == "mov" and operand_1 == "edx"):
            func_hash = operand_2
        elif (mnemonic == "mov" and operand_1 == "ecx"):
            dll_number = int(operand_2)
        elif (mnemonic == "xor" and operand_1 == operand_2 and operand_1 == "ecx"):
            dll_number = 0
    result.append((counter, caller, dll_name[dll_number],func_hash))

with open(kernel32_hashed, "r", encoding="utf-16") as file:
    kernel32_content = file.readlines()
with open(ntdll_hashed, "r", encoding="utf-16") as file:
    ntdll_content = file.readlines()
with open(wininet_hashed, "r",  encoding="utf-16") as file:
    wininet_content = file.readlines()

output = []
for tup in result:
    print(tup)
    if tup[2] == "kernel32.dll":
        searchfile = kernel32_content
    elif tup[2] == "ntdll.dll":
        searchfile = ntdll_content
    else:
        searchfile = wininet_content
    for line in searchfile:
        if tup[3][:-1].lstrip('0').lower() in line:
            helper = list(tup)
            helper.append(line.split(",")[0])
            output.append((* helper,))
            break

print(output)

for tup in output:
    print(f"{hex(tup[1])}: {tup[4]}") # as output in ida and to follow the offset by clicking on it
    set_cmt(tup[1], tup[4], 0)

# For documentation purposes
# Tuple (id, offset, module, func_hashed, func_name)
# [(1, 4198440, 'kernel32.dll', '0C1F3B876h', 'CreateToolhelp32Snapshot'), (2, 4198454, 'kernel32.dll', '8197004Ch', 'Process32FirstW'), (3, 4198472, 'kernel32.dll', '0BC6B67BFh', 'Process32NextW'), (4, 4199169, 'wininet.dll', '2B53DA6h', 'HttpQueryInfoA'), (5, 4199459, 'kernel32.dll', '7A3A310h', 'GetTempPathW'), (6, 4199473, 'kernel32.dll', '759903FCh', 'CreateDirectoryW'), (7, 4199487, 'kernel32.dll', '0A1EFE929h', 'CreateFileW'), (8, 4199505, 'kernel32.dll', '0CCE95612h', 'WriteFile'), (9, 4200377, 'kernel32.dll', '649EB9C1h', 'GetThreadContext'), (10, 4200438, 'kernel32.dll', '0F7C7AE42h', 'ReadProcessMemory'), (11, 4200487, 'ntdll.dll', '90483FF6h', 'NtUnmapViewOfSection'), (12, 4200519, 'kernel32.dll', '0E62E824Dh', 'VirtualAllocEx'), (13, 4200624, 'kernel32.dll', '4F58972Eh', 'WriteProcessMemory'), (14, 4201168, 'kernel32.dll', '5688CBD8h', 'SetThreadContext'), (15, 4201235, 'kernel32.dll', '5D180413h', 'VirtualProtectEx'), (16, 4201563, 'kernel32.dll', '3872BEB9h', 'ResumeThread'), (17, 4201815, 'kernel32.dll', '0A851D916h', 'CreateProcessA'), (18, 4201832, 'kernel32.dll', '4F58972Eh', 'WriteProcessMemory'), (19, 4201849, 'kernel32.dll', '3872BEB9h', 'ResumeThread'), (20, 4201861, 'kernel32.dll', '0E62E824Dh', 'VirtualAllocEx'), (21, 4201878, 'kernel32.dll', '9CE0D4Ah', 'VirtualAlloc'), (22, 4201895, 'kernel32.dll', '0FF808C10h', 'CreateRemoteThread'), (23, 4201965, 'wininet.dll', '0DA16A83Dh', 'InternetOpenA'), (24, 4201985, 'wininet.dll', '16505E0h', 'InternetOpenUrlA'), (25, 4202005, 'wininet.dll', '6CC098F5h', 'InternetReadFile'), (26, 4202025, 'wininet.dll', '0E5191D24h', 'InternetCloseHandle'), (27, 4202278, 'kernel32.dll', '8436F795h', 'IsDebuggerPresent')]

# Output:
# 0x401028: CreateToolhelp32Snapshot
# 0x401036: Process32FirstW
# 0x401048: Process32NextW
# 0x401301: HttpQueryInfoA
# 0x401423: GetTempPathW
# 0x401431: CreateDirectoryW
# 0x40143f: CreateFileW
# 0x401451: WriteFile
# 0x4017b9: GetThreadContext
# 0x4017f6: ReadProcessMemory
# 0x401827: NtUnmapViewOfSection
# 0x401847: VirtualAllocEx
# 0x4018b0: WriteProcessMemory
# 0x401ad0: SetThreadContext
# 0x401b13: VirtualProtectEx
# 0x401c5b: ResumeThread
# 0x401d57: CreateProcessA
# 0x401d68: WriteProcessMemory
# 0x401d79: ResumeThread
# 0x401d85: VirtualAllocEx
# 0x401d96: VirtualAlloc
# 0x401da7: CreateRemoteThread
# 0x401ded: InternetOpenA
# 0x401e01: InternetOpenUrlA
# 0x401e15: InternetReadFile
# 0x401e29: InternetCloseHandle
# 0x401f26: IsDebuggerPresent
