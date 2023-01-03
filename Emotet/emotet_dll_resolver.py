# reference: https://kienmanowar.wordpress.com/2022/12/19/z2abimonthly-malware-challege-emotet-back-from-the-dead/
# reference: https://github.com/OALabs/hashdb/blob/main/algorithms/emotet.py

import idaapi
import idautils 

ea = 0x18000F174

final_hash_values = [] 
get_operand_final_values = []
args_value = []

common_dll = ['kernel32.dll','user32.dll','ntdll.dll','shlwapi.dll','iphlpapi.dll','urlmon.dll','ws2_32.dll','crypt32.dll','shell32.dll','advapi32.dll','gdiplus.dll','gdi32.dll','ole32.dll','psapi.dll','cabinet.dll','imagehlp.dll','netapi32.dll','wtsapi32.dll','mpr.dll','wininet.dll','userenv.dll','bcrypt.dll', 'comctl32.dll', 'comdlg32.dll', 'msvcrt.dll', 'oleaut32.dll', 'srsvc.dll', 'winhttp.dll', 'advpack.dll', 'combase.dll', 'ntoskrnl.exe']

# Get operand hash values and addresses
def get_hash_val(ea):
    for xref in idautils.CodeRefsTo(ea, 0): 
        args = idaapi.get_arg_addrs(xref)[1]
        args_value.append(args)
        get_operand = get_operand_value(args, 1) & 0xffffffff
        get_operand_final = hex(get_operand)
        get_operand_final_values.append(get_operand_final)
    return args_value, get_operand_final_values
 

args_value, hash_val = get_hash_val(0x18000F174)


# Get hash values from the list of common DLLs
def hash_calc(dll_name):
    hash_value = 0
    for c in dll:
        hash_value = (((hash_value << 16) & 0xffffffff) + ((hash_value << 6) & 0xffffffff) + ord(c) - hash_value) & 0xffffffff
        final_hash_value = hash_value ^ 0x106308C0
    return final_hash_value

for dll in common_dll:
    hash_val = hash_calc(dll)
    final_hash_values.append(hex(hash_val))

common_dll_hash_val = final_hash_values

# Add the enum with the correct name and flag value
eid = ida_enum.add_enum(0, "DLL_Enum", ida_bytes.hex_flag())

# Iterate through the values in hash_val and common_dll, and add them as enum members
for operand, dll in zip(common_dll_hash_val, common_dll):
    # Make sure to pass the operand value as an integer, not a string
    ida_enum.add_enum_member(eid, '%s_hash' % dll, int(operand,16), idaapi.BADADDR)

# Retrieving enums
all_enums = ida_enum.get_enum_qty()
for i in range(0, all_enums):
    enum_id = ida_enum.getn_enum(i)
    mask = ida_enum.get_first_bmask(enum_id)
    enum_constant = ida_enum.get_first_enum_member(enum_id, mask)

# Assign enums to the operands 
for i in args_value:
    idx_operand = 1
    idc.op_enum(i, idx_operand, enum_id, 0)