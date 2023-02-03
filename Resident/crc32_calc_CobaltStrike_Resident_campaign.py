# reference: https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-2/

import idautils
import idaapi
import pefile
from crccheck.crc import Crc32Jamcrc
import os

ea = 0x61A4D440
dll_name = ['kernel32.dll', 'advapi32.dll', 'wininet.dll', 'ws2_32.dll']

win_path = os.environ['WINDIR'] # getting Windows path
system32_path = os.path.join(win_path, "system32") # getting the C:/Windows/System32 path
export_name = []
for dll in dll_name:
    dll_path = os.path.join(system32_path, dll)
    pe = pefile.PE(dll_path)

    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        export_name.append(export.name)
        

# resolve hashes and renaming the DWORDs
for xref in idautils.CodeRefsTo(ea, 1): 
    crc32_hash_addr = idaapi.get_arg_addrs(xref)[1]
    crc_32_hash_val = get_operand_value(crc32_hash_addr, 1) 
    dword_val_addr = idaapi.get_arg_addrs(xref)[3]
        
    for m in export_name:
        try:
            crc_hash = Crc32Jamcrc.calc(m)
            crc = crc_32_hash_val
        except:
            pass
        if crc == crc_hash:
            m = str(m, 'utf-8')
            get_dword_val = get_operand_value(dword_val_addr, 1)
            idc.set_name(get_dword_val, "api_"+m, SN_CHECK)
            
            
            
         