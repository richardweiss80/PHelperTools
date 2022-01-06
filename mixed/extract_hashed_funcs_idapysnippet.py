idaapi.msg_clear()

# hash = "a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611"
# description = "dropped binary, extract the crc32 hashed function names"
# return = "liste of tuples (module, hashedfunction)"
# only a quick code snippet for demonstration, how to get the hashed strings and put comments in IDA to the call functions.

path = "C:\\Users\\rwe\\Desktop\\Development\\PHelperTools\\"
dll_name = {0: "kernel32.dll", 1: "ntdll.dll", 2: "wininet.dll"} # Offset: 0x413c1c
kernel32_hashed = path + "kernel32.dll_0x6ae69f02_crc32_hashed.txt"
wininet_hashed = path + "wininet.dll_0xc7f465f7_crc32_hashed.txt"

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

with open(kernel32_hashed, "r") as file:
    kernel32_content = file.readlines()

with open(wininet_hashed, "r") as file:
    wininet_content = file.readlines()

output = []

for tup in result:
    if tup[2] == "kernel32.dll": # ntdll.dll is not used in this malware specimen
        searchfile = kernel32_content
    else:
        searchfile = wininet_content
    for line in searchfile:
        #if tuple[1][:-1] in line:
        if tup[3][:-1].lstrip('0').lower() in line:
            helper = list(tup)
            helper.append(line.split(",")[0])
            output.append((* helper,))
            break

for tup in output:
    print(f"{hex(tup[1])}: {tup[4]}") # as output in ida and to follow the offset by clicking on it.
    set_cmt(tup[1], tup[4], 0)

# For documentation purposes
# Tuple (id, offset, module, func_hashed, func_name)
# [(1, '0x401028', 'kernel32.dll', '0C1F3B876h', 'CreateToolhelp32Snapshot'), (2, '0x401036', 'kernel32.dll', '8197004Ch', 'Process32FirstW'), (3, '0x401048', 'kernel32.dll', '0BC6B67BFh', 'Process32NextW'), (4, '0x401301', 'wininet.dll', '2B53DA6h', 'HttpQueryInfoA'), (5, '0x401423', 'kernel32.dll', '7A3A310h', 'GetTempPathW'), (6, '0x401431', 'kernel32.dll', '759903FCh', 'CreateDirectoryW'), (7, '0x40143f', 'kernel32.dll', '0A1EFE929h', 'CreateFileW'), (8, '0x401451', 'kernel32.dll', '0CCE95612h', 'WriteFile'), (9, '0x4017b9', 'kernel32.dll', '649EB9C1h', 'GetThreadContext'), (10, '0x4017f6', 'kernel32.dll', '0F7C7AE42h', 'ReadProcessMemory'), (12, '0x401847', 'kernel32.dll', '0E62E824Dh', 'VirtualAllocEx'), (13, '0x4018b0', 'kernel32.dll', '4F58972Eh', 'WriteProcessMemory'), (14, '0x401ad0', 'kernel32.dll', '5688CBD8h', 'SetThreadContext'), (15, '0x401b13', 'kernel32.dll', '5D180413h', 'VirtualProtectEx'), (16, '0x401c5b', 'kernel32.dll', '3872BEB9h', 'ResumeThread'), (17, '0x401d57', 'kernel32.dll', '0A851D916h', 'CreateProcessA'), (18, '0x401d68', 'kernel32.dll', '4F58972Eh', 'WriteProcessMemory'), (19, '0x401d79', 'kernel32.dll', '3872BEB9h', 'ResumeThread'), (20, '0x401d85', 'kernel32.dll', '0E62E824Dh', 'VirtualAllocEx'), (21, '0x401d96', 'kernel32.dll', '9CE0D4Ah', 'VirtualAlloc'), (22, '0x401da7', 'kernel32.dll', '0FF808C10h', 'CreateRemoteThread'), (23, '0x401ded', 'wininet.dll', '0DA16A83Dh', 'InternetOpenA'), (24, '0x401e01', 'wininet.dll', '16505E0h', 'InternetOpenUrlA'), (25, '0x401e15', 'wininet.dll', '6CC098F5h', 'InternetReadFile'), (26, '0x401e29', 'wininet.dll', '0E5191D24h', 'InternetCloseHandle'), (27, '0x401f26', 'kernel32.dll', '8436F795h', 'IsDebuggerPresent')]

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
