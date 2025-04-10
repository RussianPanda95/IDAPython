# Author: RussianPanda
# Sample: 911981d657b02f2079375eecbd81f3d83e5fa2b8de73afad21783004cbcc512d

import idaapi
import idautils
import idc
import ida_bytes
import ida_ua
import ida_search
import ida_name
import base64
import re
import string

def find_opcode(binary_data):
    opcode = bytes.fromhex("73 74 72 69 6E 67 20 74 6F 6F 20 6C 6F 6E 67")
    
    positions = []
    pos = binary_data.find(opcode)
    
    while pos != -1:
        positions.append(pos)
        pos = binary_data.find(opcode, pos + 1)
    
    if positions:
        build_id = None
        rc4_key = None
        
        for pos in positions:
            next_bytes = binary_data[pos + len(opcode):pos + len(opcode) + 120]
            
            current_str = ""
            for i, b in enumerate(next_bytes):
                if 32 <= b <= 126:
                    current_str += chr(b)
                elif current_str:
                    build_id = current_str
                    break
            
            string_count = 0
            current_str = ""
            for b in next_bytes:
                if 32 <= b <= 126:
                    current_str += chr(b)
                else:
                    if current_str:
                        string_count += 1
                        if string_count == 3:
                            rc4_key = current_str
                            break
                        current_str = ""
            
            if build_id and rc4_key:
                break
        
        return {
            "build_id": build_id,
            "rc4_key": rc4_key
        }
    else:
        return None

def get_binary_data():
    result = bytearray()
    
    for seg_ea in idautils.Segments():
        seg_start = seg_ea
        seg_end = idc.get_segm_end(seg_ea)
        seg_size = seg_end - seg_start
        
        seg_data = idaapi.get_bytes(seg_start, seg_size)
        result.extend(seg_data)
    
    return bytes(result)

def detect_rc4_key():
    print("Detecting RC4 key automatically...")
    binary_data = get_binary_data()
    detected_info = find_opcode(binary_data)
    
    if detected_info and detected_info["rc4_key"]:
        print(f"Found RC4 key: {detected_info['rc4_key']}")
        if detected_info["build_id"]:
            print(f"Build ID: {detected_info['build_id']}")
        return detected_info["rc4_key"]
    else:
        raise Exception("Failed to detect RC4 key")

def rc4_decrypt(encrypted_data, key):
    S = list(range(256))
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    result = bytearray()
    
    for byte in encrypted_data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return result

def sanitize_name(name):
    valid_chars = string.ascii_letters + string.digits + "_"
    result = ""
    for c in name:
        if c in valid_chars:
            result += c
        else:
            result += "_"
    
    if result and not result[0].isalpha() and result[0] != '_':
        result = "_" + result
    
    if not result:
        result = "renamed_str"
    
    return result

def decrypt_string(base64_encoded, key_str):
    try:
        key_bytes = key_str.encode('utf-8')
        
        encrypted_data = base64.b64decode(base64_encoded)
        
        decrypted_data = rc4_decrypt(encrypted_data, key_bytes)
        
        try:
            is_printable = all(32 <= b <= 126 or b in (9, 10, 13) for b in decrypted_data)
            if is_printable:
                return decrypted_data.decode('utf-8')
            else:
                return decrypted_data.hex()
        except UnicodeDecodeError:
            return decrypted_data.hex()
    except Exception as e:
        return f"Error: {str(e)}"

def is_base64(s):
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    
    if re.match(pattern, s) and len(s) % 4 == 0:
        try:
            base64.b64decode(s)
            return True
        except:
            pass
    return False

def find_lea_rdx_instructions():
    result = []
    
    seg = idaapi.get_segm_by_name(".text")
    if not seg:
        return result
    
    current_addr = seg.start_ea
    
    while current_addr < seg.end_ea:
        if idc.print_insn_mnem(current_addr) == "lea" and idc.print_operand(current_addr, 0) == "rdx":
            
            op_str = idc.print_operand(current_addr, 1)
            
            str_addr = idc.get_operand_value(current_addr, 1)
            
            str_content = ida_bytes.get_strlit_contents(str_addr, -1, 0)
            
            if str_content:
                try:
                    str_content = str_content.decode('utf-8', errors='replace')
                    
                    if is_base64(str_content):
                        result.append((current_addr, str_addr, str_content))
                except:
                    pass
                    
        current_addr = idc.next_head(current_addr)
    
    return result

def find_qwords(lea_insn_addr, decrypted_str, max_instructions=20):
    qwords = []
    
    current_addr = lea_insn_addr
    end_addr = current_addr + max_instructions * 16
    
    while current_addr < end_addr:
        current_addr = idc.next_head(current_addr)
        
        if current_addr == idaapi.BADADDR:
            break
        
        if idc.print_insn_mnem(current_addr) == "lea" and idc.print_operand(current_addr, 0) == "rcx":
            op_str = idc.print_operand(current_addr, 1)
            
            if op_str.startswith("qword_"):
                qword_addr = idc.get_operand_value(current_addr, 1)
                qwords.append((current_addr, qword_addr))
        
        if idc.print_insn_mnem(current_addr) in ["ret", "jmp"]:
            break
    
    return qwords

def add_comments_and_rename():
    key = detect_rc4_key()
    
    matches = find_lea_rdx_instructions()
    
    str_count = 0
    str_var_count = 0
    qword_count = 0
    
    for insn_addr, str_addr, encrypted in matches:
        try:
            decrypted = decrypt_string(encrypted, key)
            
            comment = f"Decrypted: \"{decrypted}\""
            if idc.set_cmt(insn_addr, comment, 0):
                str_count += 1
                print(f"Added comment at 0x{insn_addr:X}: {comment}")
            
            data_comment = f"Decrypted: \"{decrypted}\""
            idc.set_cmt(str_addr, data_comment, 0)
            
            new_name = sanitize_name(f"str_{decrypted[:20]}")
            if ida_name.set_name(str_addr, new_name, ida_name.SN_CHECK):
                str_var_count += 1
                print(f"Renamed string at 0x{str_addr:X} to {new_name}")
            
            associated_qwords = find_qwords(insn_addr, decrypted)
            for qword_insn_addr, qword_addr in associated_qwords:
                qword_new_name = sanitize_name(f"qw_{decrypted[:20]}")
                if ida_name.set_name(qword_addr, qword_new_name, ida_name.SN_CHECK):
                    qword_count += 1
                    print(f"Renamed qword at 0x{qword_addr:X} to {qword_new_name}")
            
        except Exception as e:
            print(f"Error processing string at 0x{str_addr:X}: {e}")
    
    print(f"Added {str_count} decryption comments")
    print(f"Renamed {str_var_count} string variables")
    print(f"Renamed {qword_count} associated qword variables")

def main():
    add_comments_and_rename()

if __name__ == "__main__":
    main()
