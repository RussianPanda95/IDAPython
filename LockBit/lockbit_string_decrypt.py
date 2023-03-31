import idautils
import idaapi
import idc

# String decrypt function
ea = 0x10001168 
operands = []

def xor_decrypt(data, key):
    return bytes([~(b ^ key[i % len(key)]) & 0xff for i, b in enumerate(data)])
xor_key = 'FE9F0311'
key = bytes.fromhex(xor_key)

# Iterate through code references to start address
for xref in idautils.CodeRefsTo(ea, 0):
    # Move to previous instruction
    print("decrypt function at: " + hex(xref))
    prev_ea = idc.prev_head(xref)

    # Keep iterating through previous instructions until "lea" is found or beginning of function is reached
    while prev_ea >= idaapi.get_func(xref).start_ea:
        # Check if instruction is "lea"
        if idaapi.print_insn_mnem(prev_ea) == "lea":

            print("Found 'lea' instruction at address: " + hex(prev_ea))
            break

        # Check if mnem is "jnz"
        if idaapi.print_insn_mnem(prev_ea) == "jnz":
            print("Found 'jnz' instruction at address: " + hex(prev_ea))
            break
        # Check if mnem is "jz"
        if idaapi.print_insn_mnem(prev_ea) == "jz":
            print("Found 'jz' instruction at address: " + hex(prev_ea))
            break
        
        # Move to previous instruction
        prev_ea = idc.prev_head(prev_ea)

    # Iterate through "mov" after "lea"
    while prev_ea >= idaapi.get_func(xref).start_ea:
        # Check if instruction is "mov"
        if idaapi.print_insn_mnem(prev_ea) == "mov" and idaapi.get_byte(prev_ea+2) != 0xF0:
            # Get second operand and add it to list of operands
            second_operand = idc.print_operand(prev_ea, 1).replace("h", "")
            operands.append(int(second_operand, 16).to_bytes(4, byteorder="little"))
            print("Second operand of 'mov' instruction at address " + hex(prev_ea) + " is " + second_operand)
      
        elif idaapi.print_insn_mnem(prev_ea) == "push":
            # Concatenate operands and stop iterating if "push" is found
            operands_bytes = b"".join(operands)
            enc_string = operands_bytes.hex()
            data = bytes.fromhex(enc_string) 
            decrypted_operand = xor_decrypt(data, key).replace(b'\x00', b'')
            print("Encoded string: " + enc_string)

            decrypted_str = decrypted_operand.decode("utf-8", errors="ignore")
            
            # Check if the decrypted string contains printable ASCII chars 
            printable_chars = [c for c in decrypted_str if ord(c) >= 32 and ord(c) <= 126]
            if len(printable_chars) != len(decrypted_str):
                print("Decoded string contains non-printable ASCII characters, ignoring")
            else:
                print("Decoded string: " + decrypted_str)
                idc.set_cmt(xref, decrypted_str, 0) # set decrypted string as comment for xref     
            break
        # Move to next instruction
        prev_ea = idc.next_head(prev_ea)
    # Clear operands list for next iteration
    operands.clear()
    # Continue iterating if "push" is not found 
    continue
