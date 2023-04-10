import idautils
import idc
import idaapi

def xor_decrypt(data, key):
    out = []

    for i in range(len(data)):
        out.append(data[i] ^ key[i % len(key)])
    return out


# String decrypt function
ea = 0x00401085

# Find all references to the decryption function
for xref in idautils.CodeRefsTo(ea, 0):
    args = idaapi.get_arg_addrs(xref)[0]
    print(f"String decrypt function: {hex(xref)}")
    prev_ea = idc.prev_head(args)
    get_operand = idc.get_operand_value(args, 0)
    key = idc.get_bytes(get_operand, 200)

    # Check if there is a null byte within the last 40 bytes of the key
    if b"\x00" in key[-40:]:
        key = key[:len(key)-40+key[-40:].index(b"\x00")]
        

    string_addr = idc.get_operand_value(prev_ea, 0)
    data = idaapi.get_strlit_contents(string_addr, -1, idc.get_inf_attr(idc.INF_MAX_EA))
    try:
        decrypt_me = xor_decrypt(data, key)
    except:
        prev_ea_frm_dword = idc.prev_head(prev_ea)
        #print(hex(prev_ea_frm_dword))
        string_addr_frm_dword = idc.get_operand_value(prev_ea_frm_dword, 0)
        data = idaapi.get_strlit_contents(string_addr_frm_dword, -1, idc.get_inf_attr(idc.INF_MAX_EA))
        decrypt_me = xor_decrypt(data, key)

    decr_str = ''.join(map(chr, decrypt_me))
    decrypted_str = ""
    for c in decr_str:
        if ord(c) >= 32 and ord(c) <= 126:
            decrypted_str += c
    print(decrypted_str)

    # Add a comment for each decrypted string 
    idc.set_cmt(xref, f"{decrypted_str}", 1)
