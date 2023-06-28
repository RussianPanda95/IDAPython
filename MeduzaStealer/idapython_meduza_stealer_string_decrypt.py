# Author: RussianPanda
# Reference: https://github.com/X-Junior/Malware-IDAPython-Scripts/tree/main/PivateLoader
# Tested on sample https://www.unpac.me/results/7cac1177-08f5-4faa-a59e-3c7107964f0f?hash=29cf1ba279615a9f4c31d6441dd7c93f5b8a7d95f735c0daa3cc4dbb799f66d4#/

import idautils, idc, idaapi, ida_search
import re  

pattern1 = '66 0F EF'
pattern2 = 'C5 FD EF'

# Start search from end of the file
start = idc.get_segm_end(idc.get_first_seg())

addr_to_data = {}  

def search_and_process_pattern(pattern, start):
    while True:
        addr = ida_search.find_binary(start, 0, pattern, 16, ida_search.SEARCH_UP | ida_search.SEARCH_NEXT)

        if addr == idc.BADADDR:  
            break

        ptr_addr = addr 
        found_mov = False  
        data = ''  

        for _ in range(400):
            ptr_addr = idc.prev_head(ptr_addr)

            if idc.print_insn_mnem(ptr_addr) == 'call' or idc.print_insn_mnem(ptr_addr) == 'jmp' or idc.print_insn_mnem(ptr_addr) == 'jz':
                break

            if idc.print_insn_mnem(ptr_addr) == 'movaps' and re.match(r'xmm[0-9]+', idc.print_operand(ptr_addr, 1)):
                break

            if idc.print_insn_mnem(ptr_addr) == 'mov':
                # Ignore the instruction if the destination is ecx
                if idc.print_operand(ptr_addr, 0) == 'ecx' or idc.print_operand(ptr_addr, 0) == 'edx':
                    continue

                op1_type = idc.get_operand_type(ptr_addr, 0)
                op2_type = idc.get_operand_type(ptr_addr, 1)

                operand_value = idc.get_operand_value(ptr_addr, 1)  

                if (op1_type == idc.o_displ or op1_type == idc.o_reg) and op2_type == idc.o_imm and len(hex(operand_value)[2:]) >= 4:
                    hex_data = hex(idc.get_operand_value(ptr_addr, 1))[2:]
                    hex_data = hex_data.rjust(8, '0') 

                    if hex_data.endswith('ffffffff'):
                        hex_data = hex_data[:-8]
                    if hex_data.startswith('ffffffff'):
                        hex_data = hex_data[8:]

                    # Alternative method for unpacking hex data
                    bytes_data = bytes.fromhex(hex_data)
                    int_data = int.from_bytes(bytes_data, 'little')
                    hex_data = hex(int_data)[2:].rjust(8, '0')

                    data = hex_data + data  
                    found_mov = True

        if found_mov:  # Append the data only if the desired mov instruction was found
            if addr in addr_to_data:
                addr_to_data[addr] = data + addr_to_data[addr]
            else:
                addr_to_data[addr] = data

        # Continue search from the previous address
        start = addr - 1

# Search and process pattern1
search_and_process_pattern(pattern1, start)

# Reset the start variable to search for pattern2
start = idc.get_segm_end(idc.get_first_seg())

# Search and process pattern2
search_and_process_pattern(pattern2, start)

# XOR the string and key and print the decrypted strings
for addr, data in addr_to_data.items():
    if len(data) >= 10:
        string = data[:len(data)//2]
        key = data[len(data)//2:]

        # XOR the string and key
        xored_bytes = bytes([a ^ b for a, b in zip(bytes.fromhex(string), bytes.fromhex(key))])

        decrypted_string = xored_bytes.decode('utf-8', errors='ignore')

        print(f"{hex(addr)}: {decrypted_string}")
    
        # Set IDA comment at the appropriate address
        idaapi.set_cmt(addr, decrypted_string, 0)
