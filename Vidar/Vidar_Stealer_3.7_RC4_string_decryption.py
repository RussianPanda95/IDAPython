import idautils
import idc
import idaapi
from Crypto.Cipher import ARC4
import base64

# String decrypt function
ea = 0x00401420

# Find all references to the decryption function
xrefs = idautils.CodeRefsTo(ea, 0)
for xref in xrefs:

    key = b"09976218420008604394"
    cipher = ARC4.new(key)
    
    args = idaapi.get_arg_addrs(xref)[0]
    str_dec_fn = hex(xref)
    prev_ea = idc.prev_head(args)
    get_operand = idc.get_operand_value(args, 0)
    bytes_str = idc.get_bytes(get_operand, 30)
    null_index = bytes_str.find(b'\x00')
    if null_index != -1:
        bytes_str = bytes_str[:null_index]
        bytes_str = bytes_str.decode()
        dec = base64.b64decode(bytes_str)
        decr = cipher.decrypt(dec)
        
        # Add a comment with the decrypted string to the corresponding instruction
        idc.set_cmt(prev_ea, f"{decr}", 0)
        decrypted_strings.append(decr)

        