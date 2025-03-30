# Author: RussianPanda
# Samples: 9fbf5b97697355937f470d68620fe7c917f48831731bdd43e9a48f0f02f73030
# b0a567a7b1704d8794c58be47afa3b375677b5b4c2afd9e43128ee0afa0ade42

import ida_bytes
import ida_segment
import ida_funcs
import ida_ua
import idaapi
import idc
import idautils
import os
import binascii
import base64
import re

def extract_base_value_from_fn(func_addr):
    func = ida_funcs.get_func(func_addr)
    if not func:
        return None
    
    base_value = None
    
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        if idc.print_insn_mnem(ea) == "mov":
            if idc.get_operand_type(ea, 1) == 5:
                value = idc.get_operand_value(ea, 1)
                
                if 0x300 <= value <= 0x500:
                    next_ea = ea
                    for _ in range(10):
                        next_ea = idc.next_head(next_ea)
                        if next_ea >= func.end_ea:
                            break
                            
                        if idc.print_insn_mnem(next_ea) == "sub":
                            return value
    
    return base_value

def find_calls(pattern_addr, max_before=40, max_after=20):
    results = {
        "before": [],
        "after": []
    }
    
    current = pattern_addr
    for _ in range(max_before):
        prev = idc.prev_head(current)
        if prev == idaapi.BADADDR:
            break
            
        if ida_bytes.get_byte(prev) == 0xE8:
            offset = ida_bytes.get_dword(prev + 1)
            target = prev + 5 + offset
            results["before"].append((prev, target))
            
        current = prev
    
    lea_ea = pattern_addr + 5
    if lea_ea != idaapi.BADADDR:
        lea_size = idc.get_item_size(lea_ea)
        if lea_size > 0:
            current = lea_ea + lea_size
            
            for _ in range(max_after):
                if current == idaapi.BADADDR:
                    break
                    
                if ida_bytes.get_byte(current) == 0xE8:
                    offset = ida_bytes.get_dword(current + 1)
                    target = current + 5 + offset
                    results["after"].append((current, target))
                    
                current = idc.next_head(current)
    
    return results

def analyze_fn(func_addr, base_values):
    func = ida_funcs.get_func(func_addr)
    if not func:
        return None
    
    immediates = []
    
    ea = func.start_ea
    while ea < func.end_ea:
        insn_len = ida_ua.decode_insn(ida_ua.insn_t(), ea)
        if insn_len == 0:
            ea += 1
            continue
            
        disasm = idc.generate_disasm_line(ea, 0)
        
        if "mov" in disasm.lower() and ", " in disasm:
            parts = disasm.split(", ")
            if len(parts) == 2:
                val_part = parts[1].strip()
                try:
                    if "0x" in val_part:
                        value = int(val_part.split("0x")[1].split()[0], 16)
                    elif val_part.endswith("h"):
                        value = int(val_part[:-1], 16)
                    elif val_part.isdigit():
                        value = int(val_part)
                    else:
                        ea += insn_len
                        continue
                        
                    immediates.append(value)
                except ValueError:
                    pass
        
        ea += insn_len
    
    for base in base_values:
        for val in immediates:
            if val < base:
                result = base - val
                if 32 <= result <= 126:
                    return chr(result)
    
    for val1 in immediates:
        for val2 in immediates:
            if val1 == val2:
                continue
                
            result = val1 - val2
            if 32 <= result <= 126:
                return chr(result)
    
    return None

def find_string_chars(pattern_addr, global_base_values):
    """Find all possible characters for a pattern"""
    calls = find_calls(pattern_addr)
    
    first_char = None
    last_char = None
    
    pattern_base_values = []
    
    for _, target in calls["before"]:
        base_value = extract_base_value_from_fn(target)
        if base_value:
            pattern_base_values.append(base_value)
    
    for _, target in calls["after"]:
        base_value = extract_base_value_from_fn(target)
        if base_value:
            pattern_base_values.append(base_value)
    
    base_values_to_use = pattern_base_values if pattern_base_values else global_base_values
    
    for call_addr, target in calls["before"]:
        char = analyze_fn(target, base_values_to_use)
        if char:
            first_char = char
            break
    
    for call_addr, target in calls["after"]:
        char = analyze_fn(target, base_values_to_use)
        if char:
            last_char = char
            break
    
    result = ""
    if first_char:
        result += first_char
    if last_char:
        result += last_char
        
    return result

def deduplicate_string(duplicated_string):
    if not duplicated_string:
        return ""
        
    fixed_string = ""
    i = 0
    while i < len(duplicated_string):
        fixed_string += duplicated_string[i]
        
        if i+1 < len(duplicated_string) and duplicated_string[i] == duplicated_string[i+1]:
            i += 2
        else:
            i += 1
            
    return fixed_string

def add_base64_padding(data):
    return data + '=' * (-len(data) % 4)

def decode_base64_with_custom_alphabet(encoded_data, custom_alphabet):
    standard_b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    translation_table = str.maketrans(custom_alphabet, standard_b64_alphabet)
    
    standard_b64_data = encoded_data.translate(translation_table)
    
    padded_data = add_base64_padding(standard_b64_data)
    
    return base64.b64decode(padded_data)
    
def extract_and_print_config_details(decoded_text):
    print("\n" + "=" * 50)
    print("EXTRACTED CONFIGURATION")
    print("=" * 50)
    
    user_value = None
    build_id_value = None
    url = None
    
    applescript_pattern = r'user: ([A-Za-z0-9+/=\-_]+)\\".*?BuildID: ([A-Za-z0-9+/=\-_]+)\\"'
    applescript_match = re.search(applescript_pattern, decoded_text)
    
    if applescript_match:
        user_value = applescript_match.group(1)
        build_id_value = applescript_match.group(2)
    else:
        user_match = re.search(r'user:\s*([A-Za-z0-9+/=\-_]+)[\\"]', decoded_text)
        if user_match:
            user_value = user_match.group(1)
        
        build_match = re.search(r'BuildID:\s*([A-Za-z0-9+/=\-_]+)[\\"]', decoded_text)
        if build_match:
            build_id_value = build_match.group(1)
    
    url_match = re.search(r'http[s]?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[a-z]+', decoded_text)
    if url_match:
        url = url_match.group(0)
    
    if user_value:
        print(f"User: {user_value}")
    if build_id_value:
        print(f"BuildID: {build_id_value}")
    if url:
        print(f"C2 URL: {url}")
    
    print("=" * 50)
    
    
    summary = ""
    if user_value:
        summary += f"User: {user_value}\n"
    if build_id_value:
        summary += f"BuildID: {build_id_value}\n"
    if url:
        summary += f"C2 URL: {url}\n"
    
    if summary:
        idaapi.info(f"Extracted Configuration\n\n{summary}")
    
    return summary

def generate_string():
    print("AMOS Stealer Configuration Extractor")
    print("=" * 50)
    
    seg = ida_segment.get_segm_by_name("__text")
    if not seg:
        seg = ida_segment.get_first_seg()
    
    start_ea = seg.start_ea
    end_ea = seg.end_ea
    
    pattern_addrs = []
    current_ea = start_ea
    
    print("Scanning for patterns...")
    while current_ea < end_ea:
        if (ida_bytes.get_byte(current_ea) == 0xE9 and 
            ida_bytes.get_dword(current_ea + 1) == 0):
            
            next_ea = current_ea + 5
            if next_ea < end_ea and ida_bytes.get_byte(next_ea) == 0x48 and ida_bytes.get_byte(next_ea + 1) == 0x8D:
                pattern_addrs.append(current_ea)
            
        current_ea = idc.next_head(current_ea)
    
    print(f"Found {len(pattern_addrs)} patterns")
    
    print("Collecting global base values...")
    global_base_values = []
    
    for addr in pattern_addrs[:min(50, len(pattern_addrs))]:
        calls = find_calls(addr)
        
        for _, target in calls["before"] + calls["after"]:
            base_value = extract_base_value_from_fn(target)
            if base_value and base_value not in global_base_values:
                global_base_values.append(base_value)
                print(f"Found base value: {hex(base_value)}")
    
    print(f"Found {len(global_base_values)} global base values: {[hex(x) for x in global_base_values]}")
    
    pattern_chars = {}
    
    for i, addr in enumerate(pattern_addrs):
        if i % 5000 == 0:
            print(f"Processed {i}/{len(pattern_addrs)} patterns")
            
        chars = find_string_chars(addr, global_base_values)
        
        if chars:
            pattern_chars[addr] = chars
    
    print(f"Found characters for {len(pattern_chars)} patterns")
    
    strings = {}
    sorted_addrs = sorted(pattern_chars.keys())
    
    if sorted_addrs:
        current_string = ""
        current_start = None
        
        for i, addr in enumerate(sorted_addrs):
            if current_start is None:
                current_start = addr
                current_string = pattern_chars[addr]
                continue
            
            if i > 0 and addr - sorted_addrs[i-1] < 200:
                current_string += pattern_chars[addr]
            else:
                if len(current_string) > 2:
                    deduped_string = deduplicate_string(current_string)
                    
                    if len(deduped_string) > 2000 or len(deduped_string) == 128:
                        strings[current_start] = deduped_string
                
                current_start = addr
                current_string = pattern_chars[addr]
        
        if current_start and len(current_string) > 2:
            deduped_string = deduplicate_string(current_string)
            
            if len(deduped_string) > 2000 or len(deduped_string) == 128:
                strings[current_start] = deduped_string
    
    print(f"Found {len(strings)} strings matching criteria")
    
    output_dir = r"C:\russianpanda"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    #output_file = os.path.join(output_dir, "filtered_strings.txt")
    
    alphabet_string = None
    encoded_data_string = None
    
    for addr, string in sorted(strings.items()):
        if len(string) == 128:
            alphabet_string = string
            alphabet_addr = addr
        elif len(string) > 2000:
            encoded_data_string = string
            encoded_addr = addr
    
    with open(output_file, "w") as f:
        
        for addr, string in sorted(strings.items()):
            f.write(f"String at 0x{addr:X}: \"{string}\"\n")
            f.write(f"Length: {len(string)}\n")
            
            hex_string = ' '.join(f"{ord(c):02X}" for c in string)
            f.write(f"Hex: {hex_string}\n\n")
            
       
    decoded_text = None
    
    if alphabet_string and encoded_data_string:
        try:
            print("\nAttempting to decode using custom Base64...")
            print(f"Custom alphabet found at 0x{alphabet_addr:X} (length: {len(alphabet_string)})")
            print(f"Encoded data found at 0x{encoded_addr:X} (length: {len(encoded_data_string)})")
            
            alphabet_binary = binascii.unhexlify(alphabet_string)
            custom_alphabet = alphabet_binary.decode(errors="ignore")
            
            encoded_binary = binascii.unhexlify(encoded_data_string)
            encoded_data = encoded_binary.decode(errors="ignore")
            
            decoded_data = decode_base64_with_custom_alphabet(encoded_data, custom_alphabet)
            decoded_text = decoded_data.decode(errors="replace")
            
            decoded_file = os.path.join(output_dir, "decoded_config.txt")
            with open(decoded_file, "w") as f:
                f.write(decoded_text)
            
            print(f"\nDecoded data saved to {decoded_file}")
            
            extract_and_print_config_details(decoded_text)
            
        except Exception as e:
            print(f"Error during decoding process: {e}")
    else:
        if not alphabet_string:
            print("\nCould not find a 128-byte string for the custom alphabet.")
        if not encoded_data_string:
            print("\nCould not find a blob for the encoded data.")
    
    return strings

try:
    generate_string()
except Exception as e:
    print(f"Error: {str(e)}")
    import traceback
    traceback.print_exc()