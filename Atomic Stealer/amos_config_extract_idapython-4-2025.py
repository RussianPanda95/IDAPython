# Author: RussianPanda
# Sample: e37d314adb19bb463dd3257d5609df37d1fbe3eb21567b89b7d3352ee23451d7

import ida_bytes
import ida_segment
import ida_funcs
import ida_ua
import idaapi
import idc
import idautils
import re
import binascii
import base64
import traceback

def extract_chr_from_fn(func_addr):
    func = ida_funcs.get_func(func_addr)
    if not func:
        return None
    
    ea = func.start_ea
    while ea < func.end_ea:
        if idc.print_insn_mnem(ea) == "mov" and idc.print_operand(ea, 0) == "eax":
            if idc.get_operand_type(ea, 1) == 5:
                base_value = idc.get_operand_value(ea, 1)
                
                next_ea = idc.next_head(ea)
                if next_ea < func.end_ea and idc.print_insn_mnem(next_ea) == "sub":
                    if idc.print_operand(next_ea, 0) == "eax":
                        if idc.get_operand_type(next_ea, 1) == 4:
                            var_name = idc.print_operand(next_ea, 1)
                            
                            for search_ea in range(func.start_ea, next_ea):
                                if idc.print_insn_mnem(search_ea) == "mov":
                                    if idc.print_operand(search_ea, 0) == var_name:
                                        sub_value = idc.get_operand_value(search_ea, 1)
                                        result = base_value - sub_value
                                        
                                        if 32 <= result <= 126:
                                            return chr(result)
        
        ea = idc.next_head(ea)
    
    return None

def is_hex_str(s, min_ratio=0.9):
    hex_chars = sum(1 for c in s if c in '0123456789abcdefABCDEF')
    return hex_chars / len(s) >= min_ratio if len(s) > 0 else False

def add_base64_padding(data):
    return data + '=' * (-len(data) % 4)

def decode_base64_with_custom_alphabet(encoded_data, custom_alphabet, chunk_size=10000):
    standard_b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    try:
        alphabet_bin = binascii.unhexlify(custom_alphabet)
        custom_alphabet_str = alphabet_bin.decode('utf-8', errors='replace')
        
        sample_encoded = encoded_data[:min(1000, len(encoded_data))]
        encoded_bin_sample = binascii.unhexlify(sample_encoded)
        encoded_sample_str = encoded_bin_sample.decode('utf-8', errors='replace')
        
        encoded_chunks = []
        for i in range(0, len(encoded_data), chunk_size*2):  # *2 because each hex char is 0.5 bytes
            chunk = encoded_data[i:i+chunk_size*2]
            encoded_bin = binascii.unhexlify(chunk)
            encoded_str = encoded_bin.decode('utf-8', errors='replace')
            encoded_chunks.append(encoded_str)
        
        encoded_data_str = ''.join(encoded_chunks)
        
    except Exception as e:
        print(f"Error converting hex: {str(e)}")
        return None
    
    if len(custom_alphabet_str) > 64:
        custom_alphabet_str = custom_alphabet_str[:64]
        print(f"Trimmed alphabet to 64 characters")
    elif len(custom_alphabet_str) < 64:
        padding_needed = 64 - len(custom_alphabet_str)
        custom_alphabet_str += "A" * padding_needed
        print(f"Padded alphabet with {padding_needed} 'A's")
    
    translation_table = str.maketrans(custom_alphabet_str, standard_b64_alphabet)
    
    decoded_chunks = []
    total_length = len(encoded_data_str)
    
    for i in range(0, total_length, chunk_size):
        chunk = encoded_data_str[i:i+chunk_size]
        
        standard_b64_chunk = chunk.translate(translation_table)
        
        for approach in range(3):
            try:
                if approach == 0:
                    padded_data = add_base64_padding(standard_b64_chunk)
                    decoded_chunk = base64.b64decode(padded_data)
                elif approach == 1:
                    decoded_chunk = base64.b64decode(standard_b64_chunk)
                else:
                    decoded_chunk = base64.b64decode(standard_b64_chunk + "==")
                
                decoded_chunks.append(decoded_chunk)
                break
            except Exception as e:
                if approach == 2:
                    print(f"Failed to decode chunk at position {i}: {str(e)}")
    
    if decoded_chunks:
        return b''.join(decoded_chunks)
    
    return None

def extract_config_from_text(decoded_text):
    config = {}
    
    user_patterns = [
        r'user:\s*([A-Za-z0-9+/=\-_]+)[\\"]',
        r'[uU]ser[^:]*:\s*["\']?([A-Za-z0-9+/=\-_]+)["\']?'
    ]
    
    for pattern in user_patterns:
        match = re.search(pattern, decoded_text)
        if match:
            config['user'] = match.group(1)
            break
    
    build_patterns = [
        r'BuildID:\s*([A-Za-z0-9+/=\-_]+)[\\"]', 
        r'[bB]uild[^:]*:\s*["\']?([A-Za-z0-9+/=\-_]+)["\']?'
    ]
    
    for pattern in build_patterns:
        match = re.search(pattern, decoded_text)
        if match:
            config['build_id'] = match.group(1)
            break
    
    url_patterns = [
        r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[a-zA-Z0-9_/\-\.]+',
        r'https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/[a-zA-Z0-9_/\-\.]+',
        r'https?://[^/\s"\']+'
    ]
    
    for pattern in url_patterns:
        match = re.search(pattern, decoded_text)
        if match:
            config['url'] = match.group(0)
            break
    
    return config

def find_close_chr(funcs, start_idx, direction=1, max_distance=100):
    chars = []
    current_idx = start_idx
    prev_func = funcs[start_idx]
    
    while 0 <= current_idx < len(funcs):
        current_idx += direction
        if current_idx < 0 or current_idx >= len(funcs):
            break
            
        current_func = funcs[current_idx]
        distance = abs(current_func - prev_func)
        
        if distance > max_distance:
            break
            
        char = extract_chr_from_fn(current_func)
        if char:
            chars.append((current_func, char))
            prev_func = current_func
        else:
            break
    
    return chars

def extract_str(funcs, start_idx, max_distance=100):
    start_func = funcs[start_idx]
    start_char = extract_chr_from_fn(start_func)
    if not start_char:
        return None, None
    
    forward_chars = find_close_chr(funcs, start_idx, 1, max_distance)
    backward_chars = find_close_chr(funcs, start_idx, -1, max_distance)
    
    backward_chars.reverse()
    all_chars = backward_chars + [(start_func, start_char)] + forward_chars
    
    string = ''.join(char for _, char in all_chars)
    start_addr = all_chars[0][0] if all_chars else start_func
    
    return start_addr, string

def ad_extact():
    print("=" * 50)
    
    funcs = []
    for ea in idautils.Functions():
        funcs.append(ea)
    
    print(f"Found {len(funcs)} total functions")
    
    funcs.sort()
    
    sample_rate = 100
    samples = []
    for i in range(0, len(funcs), sample_rate):
        samples.append(i)
    
    print(f"Testing {len(samples)} sample functions...")
    
    strings = {}
    for i, idx in enumerate(samples):
        if i % 10 == 0:
            print(f"Testing sample {i}/{len(samples)}...")
            
        if idx >= len(funcs):
            continue
            
        start_addr, string = extract_str(funcs, idx)
        if string and len(string) > 10:
            strings[start_addr] = string
            print(f"Found string at 0x{start_addr:X}, length={len(string)}")
    
    hex_strings = {}
    hex_alphabet_candidates = []
    hex_encoded_data_candidates = []
    
    for addr, string in strings.items():
        if is_hex_str(string):
            hex_strings[addr] = string
            
            if 120 <= len(string) <= 140:
                hex_alphabet_candidates.append((addr, string))
                print(f"Found potential hex-encoded alphabet at 0x{addr:X}, length={len(string)}")
            
            elif len(string) > 500:
                hex_encoded_data_candidates.append((addr, string))
                print(f"Found potential hex-encoded data at 0x{addr:X}, length={len(string)}")
    
    print(f"Found {len(hex_alphabet_candidates)} potential hex-encoded alphabets")
    print(f"Found {len(hex_encoded_data_candidates)} potential hex-encoded data blocks")
    
    if hex_alphabet_candidates and hex_encoded_data_candidates:
        for alpha_idx, (alpha_addr, alphabet) in enumerate(hex_alphabet_candidates):
            for data_idx, (data_addr, encoded_data) in enumerate(hex_encoded_data_candidates):
                
                sample_size = min(10000, len(encoded_data))
                sample_data = encoded_data[:sample_size]
                
                decoded_data = decode_base64_with_custom_alphabet(sample_data, alphabet)
                
                if decoded_data:
                    print("  Initial decoding successful, decoding full data...")
                    
                    full_decoded_data = decode_base64_with_custom_alphabet(encoded_data, alphabet)
                    
                    if full_decoded_data:
                        None
                        
                        try:
                            decoded_text = full_decoded_data.decode('utf-8', errors='replace')
                            
                            print(f"  First 200 chars of decoded text: {decoded_text[:200]}...")
                            
                            config = extract_config_from_text(decoded_text)
                            
                            if config:
                                print("\n  Extracted Configuration:")
                                for key, value in config.items():
                                    print(f"  {key.capitalize()}: {value}")
                                
                                config_str = "\n".join([f"{key.capitalize()}: {value}" for key, value in config.items()])
                                idaapi.info(f"AMOS Stealer Configuration\n\n{config_str}")
                                
                                return True
                            else:
                                print("  No configuration found in decoded text")
                        except Exception as e:
                            print(f"  Error interpreting as text: {str(e)}")
                    else:
                        print("  Full decoding failed")
                else:
                    print("  Initial decoding failed")
        
        print("\nAll decoding attempts failed")
    else:
        print("Not enough candidates for decoding")
        if not hex_alphabet_candidates:
            print("Missing hex-encoded alphabet candidates")
        if not hex_encoded_data_candidates:
            print("Missing hex-encoded data candidates")
    
    return False

def scan_for_strings_by_size():
    print("=" * 50)
    
    target_sizes = {
        (120, 140): "alphabet",
        (500, 60000): "encoded"
    }
    
    segments = []
    for seg in idautils.Segments():
        segments.append((idc.get_segm_start(seg), idc.get_segm_end(seg)))
    
    print(f"Found {len(segments)} segments")
    
    strings = {}
    hex_alphabet_candidates = []
    hex_encoded_data_candidates = []
    
    for seg_start, seg_end in segments:
        print(f"Scanning segment 0x{seg_start:X} - 0x{seg_end:X}")
        
        funcs_in_segment = []
        for ea in idautils.Functions(seg_start, seg_end):
            funcs_in_segment.append(ea)
        
        funcs_in_segment.sort()
        
        i = 0
        while i < len(funcs_in_segment):
            current_addr = funcs_in_segment[i]
            char = extract_chr_from_fn(current_addr)
            
            if char:
                string = char
                last_addr = current_addr
                j = i + 1
                
                while j < len(funcs_in_segment):
                    next_addr = funcs_in_segment[j]
                    next_char = extract_chr_from_fn(next_addr)
                    
                    if next_addr - last_addr < 100 and next_char:
                        string += next_char
                        last_addr = next_addr
                        j += 1
                        
                        if len(string) % 5000 == 0 and len(string) > 0:
                            print(f"  Built string of length {len(string)}...")
                            
                        for (min_size, max_size), type_name in target_sizes.items():
                            if min_size <= len(string) <= max_size:
                                break
                    else:
                        break
                
                for (min_size, max_size), type_name in target_sizes.items():
                    if min_size <= len(string) <= max_size:
                        strings[current_addr] = string
                        print(f"Found {type_name} string at 0x{current_addr:X}, length={len(string)}")
                        
                        if is_hex_str(string):
                            if type_name == "alphabet":
                                hex_alphabet_candidates.append((current_addr, string))
                            elif type_name == "encoded":
                                hex_encoded_data_candidates.append((current_addr, string))
                        
                        break
                
                i = j
            else:
                i += 1
    
    print(f"Found {len(hex_alphabet_candidates)} potential hex-encoded alphabets")
    print(f"Found {len(hex_encoded_data_candidates)} potential hex-encoded data blocks")
    
    if hex_alphabet_candidates and hex_encoded_data_candidates:
        for alpha_idx, (alpha_addr, alphabet) in enumerate(hex_alphabet_candidates):
            
            for data_idx, (data_addr, encoded_data) in enumerate(hex_encoded_data_candidates):
                
                sample_size = min(10000, len(encoded_data))
                sample_data = encoded_data[:sample_size]
                
                decoded_data = decode_base64_with_custom_alphabet(sample_data, alphabet)
                
                if decoded_data:
                    
                    full_decoded_data = decode_base64_with_custom_alphabet(encoded_data, alphabet)
                    
                    if full_decoded_data:
                        None
                        
                        try:
                            decoded_text = full_decoded_data.decode('utf-8', errors='replace')
                                                        
                            config = extract_config_from_text(decoded_text)
                            
                            if config:
                                print("\n  Extracted Configuration:")
                                for key, value in config.items():
                                    print(f"  {key.capitalize()}: {value}")
                                
                                config_str = "\n".join([f"{key.capitalize()}: {value}" for key, value in config.items()])
                                idaapi.info(f"AMOS Stealer Configuration\n\n{config_str}")
                                
                                return True
                            else:
                                print("  No configuration found in decoded text")
                        except Exception as e:
                            print(f"  Error interpreting as text: {str(e)}")
                    else:
                        print("  Full decoding failed")
                else:
                    print("  Initial decoding failed")
        
        print("\nAll size-based decoding attempts failed")
    else:
        print("Not enough size-based candidates for decoding")
    
    return False

def main():
    print("AMOS Stealer Configuration Extractor")
    print("=" * 50)
    
    if scan_for_strings_by_size():
        return True
    
    if ad_extact():
        return True
    
    print("\nFailed to extract configuration")
    return False

try:
    success = main()
    if success:
        None
    else:
        print("\nFailed to extract configuration")
except Exception as e:
    print(f"Error: {str(e)}")
    traceback.print_exc()