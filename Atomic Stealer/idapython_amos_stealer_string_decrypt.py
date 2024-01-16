# Author: RussianPanda
# Sample: 57db36e87549de5cfdada568e0d86bff

import idautils
import idc
import idaapi
import ida_funcs
import yara
import ctypes

def hex_string_to_byte_array(hex_string):
    return bytearray.fromhex(hex_string)

def decrypt_data(data, byte_data, length, decimal_value):
    if not (byte_data[9] & 1):
        for i in range(length):
            if data[i] == data[i + 1] + 1:
                byte_data[i + 10] ^= (byte_data[i + 1] + 1)
            elif data[i] == data[i + 1] + 2:
                byte_data[i + 10] ^= (byte_data[i + 1] + 2)
            elif data[i] == data[i + 1]:
                byte_data[i + 10] ^= ctypes.c_uint8(i + decimal_value).value
            elif data[i] == data[i + 1] + 4:
                byte_data[i + 10] ^= (byte_data[i + 1] + 3)
            elif data[i] == data[i + 1] + 5:
                byte_data[i + 10] ^= (byte_data[i + 1] +  4)
            data[i] += 1

def hex_to_readable_string(hex_string):
    bytes_object = bytes.fromhex(hex_string)
    return ''.join(chr(byte) for byte in bytes_object if 32 <= byte <= 127)

def main(hex_data, decimal_value):
    data_length = len(hex_data) // 2
    byte_data = hex_string_to_byte_array(hex_data)
    data = [0] * data_length
    try:
        decrypt_data(data, byte_data, data_length - 10, decimal_value)
        decrypted_hex_data = ''.join(f"{byte:02X}" for byte in byte_data)
        readable_string = hex_to_readable_string(decrypted_hex_data)
    except IndexError as e:
        #print(f"Error occurred during decryption: {e}")
        readable_string = "Decryption Error"

    return readable_string

# Define YARA rule
str_scan_rule_one = 'rule str_scan { strings: $b = {48 8B 85 ?? ?? FF FF 48 63 8D ?? ?? FF FF 0F BE 04 08 8B 8D ?? ?? FF FF} condition: $b }'
str_scan_rules_one = yara.compile(sources={'str_scan_rule': str_scan_rule_one})

str_scan_rule_two = 'rule str_scan_two { strings: $a = {48 8B 45 ?? 48 63 4D ?? 0F BE 04 08 8B 4D ?? 83 C1 ??31 C8 88 C2} condition: $a }'
str_scan_rules_two = yara.compile(sources={'str_scan_rule': str_scan_rule_two})

def get_segment_data(segment):
    start = segment.start_ea
    end = segment.end_ea
    return idc.get_bytes(start, end - start)

def hex_to_decimal(hex_string):
    try:
        return int(hex_string, 16)
    except ValueError:
        return None
        
def is_pattern(mnemonic, op1, op2):
    if mnemonic == "movups" and op1 == "xmm0" and "cs:" in op2:
        return "xmmword" in op2 or "__" in op2
    elif mnemonic == "mov" and "cs:" in op2:
        return ("dword" in op2 or "qword_" in op2) and op1 != "xmm0"
    return False

# Read memory content from an operand and assign the raw hex value to 'value'
def read_mem_from_operand(operand):
    if ':' in operand:
        address = idc.get_name_ea_simple(operand.split(":")[1])
    else:
        address = idc.get_name_ea_simple(operand)

    if address != idaapi.BADADDR:
        # Determine the number of bytes to read based on the operand type
        if "dword" in operand:
            bytes_to_read = 4  # dword = 4 bytes
        elif "qword" in operand:
            bytes_to_read = 8  # qword = 8 bytes
        else:
            bytes_to_read = 16  # Default to 16 bytes for other types

        data = idaapi.get_bytes(address, bytes_to_read)
        if data:
            hex_value = ''.join(format(byte, '02x') for byte in data)
            return hex_value
    return None


def add_ida_comment(address, comment):
    idc.set_cmt(address, comment, 0)

def hex_string_to_decimal(hex_str):
    if hex_str.endswith('h'):
        return int(hex_str[:-1], 16)
    return None


def hex_to_signed_decimal(hex_string):
    # Assumes the hexadecimal string represents a signed 8-bit integer
    number = int(hex_string, 16)
    if number >= 2**7:  # 2**7 is 128, which is the boundary for a signed 8-bit integer
        number -= 2**8  # Adjust for negative values
    return number
    
def hex_to_signed_8bit(hex_string):
    last_8_bits_hex = hex_string[-2:]
    is_negative_8bit = int(last_8_bits_hex[0], 16) >= 8
    if is_negative_8bit:
        return int(last_8_bits_hex, 16) - (1 << 8)
    else:
        return int(last_8_bits_hex, 16)

def find_second_lea_for_zero_len_str(function_ea, decryption_decimal_value):
    lea_count = 0
    last_compare_value = None
    found_second_lea = False
    for insn_ea in idautils.FuncItems(function_ea):
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, insn_ea) > 0:
            if insn.get_canon_mnem() == "lea":
                lea_count += 1
                if lea_count == 2:
                    found_second_lea = True
                    second_operand = idc.print_operand(insn.ea, 1)
                    address = idc.get_operand_value(insn.ea, 1)

            if found_second_lea and insn.get_canon_mnem() == "cmp":
                op2 = idc.print_operand(insn.ea, 1)
                compare_value = hex_string_to_decimal(op2)
                if compare_value is not None:
                    last_compare_value = compare_value

    decrypted_lea_data = ""
    if last_compare_value is not None and found_second_lea:
        total_length = last_compare_value + 13
        lea_data = idaapi.get_bytes(address, total_length)
        if lea_data:
            lea_data_hex = ''.join(format(byte, '02x') for byte in lea_data)
            #print(f"Data at address 0x{address:x} (length: {total_length} bytes): {lea_data_hex}")

            # Decrypt the LEA data
            byte_data = hex_string_to_byte_array(lea_data_hex)
            data = [0] * len(byte_data)
            try:
                decrypt_data(data, byte_data, len(byte_data) - 10, decryption_decimal_value)
                decrypted_hex_data = ''.join(f"{byte:02X}" for byte in byte_data)
                decrypted_lea_data = hex_to_readable_string(decrypted_hex_data)
            except IndexError as e:
                print(f"Error occurred during decryption of data at LEA: {e}")

        else:
            print(f"Failed to read data from address 0x{address:x}.")

    return decrypted_lea_data

# Iterate over all segments
for seg_ea in idautils.Segments():
    segment = idaapi.getseg(seg_ea)
    segment_data = get_segment_data(segment)

    if segment_data:
        # Get matches for both rules
        matches_one = str_scan_rules_one.match(data=segment_data)
        matches_two = str_scan_rules_two.match(data=segment_data)

        # Combine matches from both rules
        combined_matches = matches_one + matches_two

        for match in combined_matches:
            for string in match.strings:
                offset, _, _ = string
                match_address = segment.start_ea + offset
                function = ida_funcs.get_func(match_address)
                if function:
                    function_name = idc.get_func_name(match_address)
                    #print(f"YARA pattern matched in function: {function_name} at address: 0x{match_address:x}")

                    decimal_values = []  

                    current_address = match_address
                    for _ in range(5):
                        insn = idaapi.insn_t()
                        idaapi.decode_insn(insn, current_address)
                        if insn.get_canon_mnem() == "add":
                            operand_value = insn.ops[1].value
                            if insn.ops[1].type == idaapi.o_imm:
                                hex_value = hex(operand_value).rstrip("L").lstrip("0x") or "0"
                                decimal_value = hex_to_signed_8bit(hex_value)
                                decimal_values.append(decimal_value)  # Store each decimal value
                                #print(f"    0x{current_address:x}: 'add' instruction (Hex: {hex_value} -> Decimal: {decimal_value})")
                                
                        current_address = idaapi.next_head(current_address, idaapi.getseg(current_address).end_ea)

                    # Scanning previous instructions until 'call' is found
                    call_address = None
                    current_address = match_address
                    while current_address >= function.start_ea:
                        insn = idaapi.insn_t()
                        if idaapi.decode_insn(insn, current_address) > 0:
                            if insn.get_canon_mnem() == "call":
                                call_address = current_address
                                called_function = idaapi.get_name(idc.get_operand_value(current_address, 0))
                                called_func_ea = idc.get_name_ea_simple(called_function)
                                
                                #print(f"    Previous 'call' instruction at: 0x{call_address:x} calling function: {called_function} at address: 0x{called_func_ea:x}")
                    
                                # Enter the called function and analyze the first 57 instructions
                                if called_func_ea != idaapi.BADADDR:
                                    current_address = called_func_ea
                                    values = []
                                    temp_values = []
                                    last_cmp_instruction = None
                                    last_cmp_operand = None
                                    compare_value = None
                                    additional_bytes = "" 
                                    for _ in range(57):
                                        insn = idaapi.insn_t()

                                        if idaapi.decode_insn(insn, current_address) > 0:
                                            #print(f"        0x{current_address:x}: {idc.generate_disasm_line(current_address, 0)}")
                                            
                                            # Check if the instruction is a 'cmp'
                                            if insn.get_canon_mnem() == "cmp":
                                                last_cmp_instruction = current_address
                                                op2 = idc.print_operand(insn.ea, 1)
                                                compare_value = hex_string_to_decimal(op2)
                                            
                                                # Print the decimal value only if it's not None
                                                if compare_value is not None:
                                                    #print(f"COMPARE VALUE: {compare_value}")
                                                    last_cmp_operand = compare_value
                                               
                
                                            mnemonic = insn.get_canon_mnem()
                                            op1 = idc.print_operand(insn.ea, 0)
                                            op2 = idc.print_operand(insn.ea, 1)
                
                                            if is_pattern(mnemonic, op1, op2) and '+0Ch' not in op2:
                                                xmmword_addr = idc.get_operand_value(insn.ea, 1)  # Store the xmmword address
                                                value = read_mem_from_operand(op2)
                                                if value:
                                                    temp_values.append(value)
                                                    #print(f"        0x{current_address:x}: {idc.generate_disasm_line(current_address, 0)} -> Value: {value}")

                                            # Process 'add' instructions within the next 5 instructions
                                            if insn.get_canon_mnem() == "add":
                                                operand_value = insn.ops[1].value
                                                if insn.ops[1].type == idaapi.o_imm:
                                                    hex_value = hex(operand_value).rstrip("L").lstrip("0x") or "0"
                                                    decimal_value = hex_to_decimal(hex_value)

                                            current_address = idaapi.next_head(current_address, idaapi.getseg(current_address).end_ea)

                                    encrypted_string = ''.join(reversed(temp_values))
                                    #print(f'Encrypted string for address 0x{match_address:x}: {encrypted_string}')
                                    values.append(encrypted_string)
                                         
                                    encrypted_string_length = len(encrypted_string) // 2  
                                    if encrypted_string_length == 0:
                                        if decimal_values:
                                            decryption_decimal_value = decimal_values[-1]
                                        else:
                                            decryption_decimal_value = None  
                                        second_lea_address = find_second_lea_for_zero_len_str(called_func_ea, decryption_decimal_value)
                                        decrypted_lea_data = find_second_lea_for_zero_len_str(called_func_ea, decryption_decimal_value)
                                        print(f"Decrypted string at LEA: {decrypted_lea_data} at 0x{call_address:x}")


                                    if decimal_values:
                                        decryption_decimal_value = decimal_values[-1]
                                        main_output = main(encrypted_string, decryption_decimal_value)
                                    else:
                                        print("No Constant Value Found for Decryption.")

                                    if compare_value is not None and (encrypted_string_length <= compare_value) and xmmword_addr:
                                        additional_bytes_address = xmmword_addr + encrypted_string_length
                                        for _ in range(11):  # Grab next 11 bytes to make a total of 12 with the current byte
                                            next_byte = idc.get_bytes(additional_bytes_address, 1)
                                            if next_byte is None:
                                                break
                                            encrypted_string += next_byte.hex()
                                            additional_bytes_address += 1

                                    if encrypted_string.endswith('000000'):
                                        encrypted_string = encrypted_string[:-6]
                                    elif encrypted_string.endswith('0000'):
                                        encrypted_string = encrypted_string[:-4]
                                    elif encrypted_string.endswith('00'):
                                        encrypted_string = encrypted_string[:-2]

                                    #print(f"Extended encrypted string for address 0x{match_address:x}: {encrypted_string}")
                    
                                    if decimal_values:
                                        decryption_decimal_value = decimal_values[-1]
                                        main_output = main(encrypted_string, decryption_decimal_value)
                                        print(f"Decrypted string at address 0x{match_address:x}: {main_output}")
                                        add_ida_comment(call_address, f"{main_output}")
                                    else:
                                        print("No Constant Value Found for Decryption.")

                                break
                        current_address = idaapi.prev_head(current_address, function.start_ea)
