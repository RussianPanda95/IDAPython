import idc
import idaapi
import idautils

ea = 0x004158D8

found = False

def xor_decrypt(data, key, size):
    out = []
    for i in range(size):
        out.append(data[i % len(data)] ^ key[i % len(key)])
    return bytes(out)
    
    
for xref in idautils.CodeRefsTo(ea, 0):
    args = idaapi.get_arg_addrs(xref)[0]
    args_size = idaapi.get_arg_addrs(xref)[2]
    key_args = idaapi.get_arg_addrs(xref)[1]
    get_operand_key = idc.get_operand_value(key_args, 1)
    #print(f"String decrypt function: {hex(xref)}")
    get_operand = idc.get_operand_value(args, 0)
    op = idc.print_operand(args_size, 0)

    if op == "esi":
        #print(f"ESI found at: {hex(args)}")
    
        # Start searching backwards from the current instruction
        current_ea = args_size
        found = False
        data_addr = idaapi.get_arg_addrs(xref)[0]
        get_operand = idc.get_operand_value(data_addr, 1)
        data = idc.get_bytes(get_operand, 20)
        data = data.replace(b"\x00", b"")
        #print(f"DATA: {data}")
        key_args = idaapi.get_arg_addrs(xref)[1]
        get_operand_key = idc.get_operand_value(key_args, 1)
        
        while not found and current_ea > 0:
            # Get the previous instruction's address
            prev_ea = idc.prev_head(current_ea)
            # Get the previous instruction's mnemonics
            prev_instr = idc.print_insn_mnem(prev_ea)

            # Check if the previous instruction matches the target operand
            if idc.print_operand(prev_ea, 0) == "esi":
                # Look for combinations of ["inc", "mov", "xor"]
                if prev_instr == "inc":
                    prev2_ea = idc.prev_head(prev_ea)
                    prev2_instr = idc.print_insn_mnem(prev2_ea)
                    if prev2_instr == "mov":
                        prev3_ea = idc.prev_head(prev2_ea)
                        prev3_instr = idc.print_insn_mnem(prev3_ea)
                        if prev3_instr == "xor":
                            # Found the combination! Print the addresses
                            #print(f"Addresses: {prev3_ea:x}, {prev2_ea:x}, {prev_ea:x}")
                            size_esi = idc.get_operand_value(prev2_ea, 0)
                            #print(f"Size of the esi: {1}")
                            #print(hex(get_operand_key))
                            key = idc.get_bytes(get_operand_key, 1)
                            decrypt_me = xor_decrypt(data, key, 1)
                            decr_str = ''.join(map(chr, decrypt_me))
                            print(f"Decrypted string: {decr_str}")
                            idc.set_cmt(xref, f"{decr_str}", 1)
                            found = True
                # Look for combinations of ["push", "pop", "push"]
                elif prev_instr == "pop":
                    prev2_ea = idc.prev_head(prev_ea)
                    prev2_instr = idc.print_insn_mnem(prev2_ea)
                    if prev2_instr == "push":
                        prev3_ea = idc.prev_head(prev2_ea)
                        prev3_instr = idc.print_insn_mnem(prev3_ea)
                        if prev3_instr == "call":
                            # Found the combination! Print the addresses
                            #print(f"Addresses: {prev3_ea:x}, {prev2_ea:x}, {prev_ea:x}")
                            size_esi = idc.get_operand_value(prev2_ea, 0)
                            #print(f"Size of the esi: {size_esi}")
                            #print(hex(get_operand_key))
                            key = idc.get_bytes(get_operand_key, size_esi)
                            #print(f"KEY: {key}")
                            decrypt_me = xor_decrypt(data, key, size_esi)
                            decr_str = ''.join(map(chr, decrypt_me))
                            print(f"Decrypted string: {decr_str}")
                            idc.set_cmt(xref, f"{decr_str}", 1)
                            found = True             
            current_ea = prev_ea
            
    if op == "edi":
        #print(f"EDI found at: {hex(args)}")

        # Start searching backwards from the current instruction
        current_ea = args_size
        found = False
        data_addr = idaapi.get_arg_addrs(xref)[0]
        get_operand = idc.get_operand_value(data_addr, 1)
        data = idc.get_bytes(get_operand, 20)
        data = data.replace(b"\x00", b"")
        #print(f"DATA: {data}")
        key_args = idaapi.get_arg_addrs(xref)[1]
        get_operand_key = idc.get_operand_value(key_args, 1)
        
        while not found and current_ea > 0:
            # Get the previous instruction's address
            prev_ea = idc.prev_head(current_ea)
            # Get the previous instruction's mnemonics
            prev_instr = idc.print_insn_mnem(prev_ea)
            # Check if the previous instruction matches the target operand
            if idc.print_operand(prev_ea, 0) == "edi":
                # Look for combinations of ["inc", "mov", "xor"]
                if prev_instr == "inc":
                    prev2_ea = idc.prev_head(prev_ea)
                    prev2_instr = idc.print_insn_mnem(prev2_ea)
                    if prev2_instr == "mov":
                        prev3_ea = idc.prev_head(prev2_ea)
                        prev3_instr = idc.print_insn_mnem(prev3_ea)
                        if prev3_instr == "xor":
                            # Found the combination! Print the addresses
                            #print(f"Addresses: {prev3_ea:x}, {prev2_ea:x}, {prev_ea:x}")
                            size_esi = idc.get_operand_value(prev2_ea, 0)
                            #print(f"Size of the edi: {1}")
                            key = idc.get_bytes(get_operand_key, 1)
                            print(hex(key_args))
                            if key == b'\xff':
                                key = b'i'
                                decrypt_me = xor_decrypt(data, key, 1)
                                decr_str = ''.join(map(chr, decrypt_me))
                                #print(f"KEY: {key}")
                                print(f"Decrypted string: {decr_str}") 
                                idc.set_cmt(xref, f"{decr_str}", 1)
                            else:
                                decrypt_me = xor_decrypt(data, key, 1)
                                decr_str = ''.join(map(chr, decrypt_me))
                                #print(f"KEY: {key}")
                                print(f"Decrypted string: {decr_str}")
                                idc.set_cmt(xref, f"{decr_str}", 1)
                            found = True
                # Look for combinations of ["inc", "mov", "xor"]
                elif prev_instr == "pop":
                    prev2_ea = idc.prev_head(prev_ea)
                    prev2_instr = idc.print_insn_mnem(prev2_ea)
                    if prev2_instr == "push":
                        prev3_ea = idc.prev_head(prev2_ea)
                        prev3_instr = idc.print_insn_mnem(prev3_ea)
                        #print(f"Addresses: {prev3_ea:x}, {prev2_ea:x}")
                        size_edi = idc.get_operand_value(prev2_ea, 0)
                        #print(f"Size of the edi: {size_edi}")
                        key = idc.get_bytes(get_operand_key, size_edi)
                        #print(f"KEY: {key}")
                        decrypt_me = xor_decrypt(data, key, size_edi)
                        decr_str = ''.join(map(chr, decrypt_me))
                        print(f"Decrypted string: {decr_str}")
                        idc.set_cmt(xref, f"{decr_str}", 1)
                        found = True
            current_ea = prev_ea

    if op == "ebx":
        #print(f"EBX found at: {hex(args)}")

        # Start searching backwards from the current instruction
        current_ea = args_size
        found = False
        data_addr = idaapi.get_arg_addrs(xref)[0]
        get_operand = idc.get_operand_value(data_addr, 1)
        data = idc.get_bytes(get_operand, 20)
        data = data.replace(b"\x00", b"")
        #print(f"DATA: {data}")
        key_args = idaapi.get_arg_addrs(xref)[1]
        get_operand_key = idc.get_operand_value(key_args, 1)
       
        while not found and current_ea > 0:
            # Get the previous instruction's address
            prev_ea = idc.prev_head(current_ea)
            # Get the previous instruction's mnemonics
            prev_instr = idc.print_insn_mnem(prev_ea)
            # Check if the previous instruction matches the target operand
            if idc.print_operand(prev_ea, 0) == "ebx":
                # Look for combinations of ["inc", "mov", "xor"]
                if prev_instr == "push":
                    prev2_ea = idc.prev_head(prev_ea)
                    prev2_instr = idc.print_insn_mnem(prev2_ea)
                    if prev2_instr == "call":
                        prev3_ea = idc.prev_head(prev2_ea)
                        prev3_instr = idc.print_insn_mnem(prev3_ea)
                        if prev3_instr == "push":
                            prev4_ea = idc.prev_head(prev3_ea)
                            prev4_instr = idc.print_insn_mnem(prev4_ea)
                            if prev4_instr == "pop":
                                prev5_ea = idc.prev_head(prev4_ea)
                                prev5_instr = idc.print_insn_mnem(prev5_ea)
                                if prev4_instr == "push":
                                    # Found the combination! Print the addresses
                                    #print(f"Addresses: {prev_ea:x}, {prev2_ea:x}, {prev3_ea:x}, {prev4_ea:x}, {prev5_ea:x}")
                                    size_ebx = idc.get_operand_value(prev2_ea, 0)
                                    #print(f"Size of the ebx: {size_ebx}")
                                    key = idc.get_bytes(get_operand_key, size_ebx)
                                    #print(f"KEY: {key}")
                                    decrypt_me = xor_decrypt(data, key, size_ebx)
                                    decr_str = ''.join(map(chr, decrypt_me))
                                    print(f"Decrypted string: {decr_str}")
                                    idc.set_cmt(xref, f"{decr_str}", 1)
                                    found = True
                elif prev_instr == "pop":
                    prev2_ea = idc.prev_head(prev_ea)
                    prev2_instr = idc.print_insn_mnem(prev2_ea)
                    if prev2_instr == "push":
                        prev3_ea = idc.prev_head(prev2_ea)
                        prev3_instr = idc.print_insn_mnem(prev3_ea)
                        #print(f"Addresses: {prev3_ea:x}, {prev2_ea:x}")
                        size_ebx = idc.get_operand_value(prev2_ea, 0)
                        #print(f"Size of the ebx: {size_ebx}")
                        key = idc.get_bytes(get_operand_key, size_ebx)
                        #print(f"KEY: {key}")
                        decrypt_me = xor_decrypt(data, key, size_ebx)
                        #print(f"DATA: {data}")
                        decr_str = ''.join(map(chr, decrypt_me))
                        print(f"Decrypted string: {decr_str}")
                        idc.set_cmt(xref, f"{decr_str}", 1)
                        found = True
            current_ea = prev_ea
    if op != "esi" and op != "edi" and op != "ebx":
        get_size = idc.get_operand_value(args_size, 0)
        data_addr = idaapi.get_arg_addrs(xref)[0]
        get_operand = idc.get_operand_value(data_addr, 1)
        data = idc.get_bytes(get_operand, 20)
        data = data.replace(b"\x00", b"")
        #print(f"DATA: {data}")
        key_args = idaapi.get_arg_addrs(xref)[1]
        get_operand_key = idc.get_operand_value(key_args, 1)
        key = idc.get_bytes(get_operand_key, get_size)
        #print(f"KEY: {key}")
        decrypt_me = xor_decrypt(data, key, get_size)
        decr_str = ''.join(map(chr, decrypt_me))
        print(f"Decrypted string: {decr_str}")
        idc.set_cmt(xref, f"{decr_str}", 1)