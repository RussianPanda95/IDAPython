# Vidar string decryptor TEST script 
# NOTE TO SELF: fix the ea's and the way the encrypted strings are passed

import idautils

ea_first = 0x401081

ea = 0x404053

readable_list = []

def xor_decrypt(data, key):
    out = []
    
    for i in range(len(data)):
        out.append(data[i] ^ key[i%len(key)])    
    return out
    
cur_addr_first = idc.prev_head(ea_first) # get first string at 0040107C
get_string_ref_first = get_operand_value(cur_addr_first, 0)
strings_first = get_string_ref_first
get_string_bytes_first_str = idc.get_bytes(strings_first, 6)
xor_key_first_str = idc.next_head(cur_addr_first)
xor_key_first_str_location = get_operand_value(xor_key_first_str,0)
read_xor_bytes_first_str = idc.get_bytes(xor_key_first_str_location, 6)
decrypt_first_str = xor_decrypt(get_string_bytes_first_str, read_xor_bytes_first_str)
decrypted_str_first = ''.join(map(chr, decrypt_first_str))
readable_list.append(decrypted_str_first)

print(decrypted_str_first)

for ref in idautils.XrefsTo(ea):
  cur_addr = idc.next_head(ref.frm)
  #print(hex(cur_addr)) 
  
  xor_key = idc.next_head(cur_addr) # xor keys address
  
  if print_insn_mnem(cur_addr) == 'pop':
    continue
        
  get_string_ref = get_operand_value(cur_addr, 0)
  
  
  strings_two = get_string_ref
  
  xor_key_bytes_location = get_operand_value(xor_key, 0)
  
  size_addr = idc.next_head(xor_key)

  #print(hex(size_addr))
  

  size = 0 
  if print_insn_mnem(size_addr) == "mov":
    if idc.print_operand(size_addr, 1) == 'ebx':
        ebx_size = 32
        #size_ebx = get_operand_value(ebx_size, 0)
        size = ebx_size

    elif idc.print_operand(size_addr, 1) == 'eax':
        eax_size = 32
        #size_eax = get_operand_value(eax_size, 0)
        size = eax_size
      
    
    elif idc.print_operand(size_addr, 1) == 'esi':
        esi_size = 32
        size = esi_size
       
  else:
   if print_insn_mnem(size_addr) == "push":
        push_size = get_operand_value(size_addr, 0)
        size = push_size


  get_string_ref = get_operand_value(cur_addr, 0)
  
  get_string_bytes = idc.get_bytes(strings_two, size)
  strings_two = get_string_ref
  #print(get_string_bytes)
  read_xor_bytes = idc.get_bytes(xor_key_bytes_location, size) # xor key
  #print(read_xor_bytes)

  try:
    decrypt_me = xor_decrypt(get_string_bytes, read_xor_bytes)
  except:
    pass
  max_size = 1000
  if len(decrypt_me) > max_size:
    continue


  decrypted_str = ''.join(map(chr, decrypt_me))
  readable_list.append(readable_str)
  print(decrypted_str)  

  idc.set_cmt(cur_addr,decrypted_str,0) #setting comments


# decrypting the strings within the pattern [call, mov, push]
for ref in idautils.XrefsTo(ea):
  cur_addr = idc.next_head(ref.frm)
  #print(hex(cur_addr)) 
  
  xor_key = idc.next_head(cur_addr) # xor keys address
  
  if print_insn_mnem(cur_addr) == 'pop':
    continue
  
  if print_insn_mnem(cur_addr) == "mov":
    next_one = idc.next_head(cur_addr)
    if print_insn_mnem(next_one) != "pop":
        string_addr = next_one
        get_str_byte_location = get_operand_value(string_addr,0)
        get_str_bytes = idc.get_bytes(get_str_byte_location, 35) # string bytes

        xor_key = next_head(string_addr) # xor keys address
        xor_key_bytes_location_2 = get_operand_value(xor_key, 0)

        get_xor_bytes = idc.get_bytes(xor_key_bytes_location_2, 35)
        
        decrypt_me = xor_decrypt(get_str_bytes, get_xor_bytes)
        decrypted_str = ''.join(map(chr, decrypt_me))
        print(decrypted_str)
        idc.set_cmt(cur_addr,decrypted_str,0) #setting comments

#decrypting strings in pattern [call, push, mov, push]
    
for ref in idautils.XrefsTo(ea):
  cur_addr = idc.next_head(ref.frm)

  
  if print_insn_mnem(cur_addr) == 'pop':
    continue
  
  if print_insn_mnem(cur_addr) == "push":
    next_one = idc.next_head(cur_addr)
    if print_insn_mnem(next_one) == "mov" and print_insn_mnem(next_one) != "pop":
        mov_addr = next_one
        enc_strings_addr = idc.prev_head(mov_addr)

        get_str_byte_location = get_operand_value(enc_strings_addr,0)
        get_str_bytes = idc.get_bytes(get_str_byte_location, 35) # string bytes

        mov_next_frm_enc_string_addr = idc.next_head(enc_strings_addr)
        xor_key = next_head(mov_next_frm_enc_string_addr) # xor keys address
        xor_key_bytes_location_2 = get_operand_value(xor_key, 0)
        get_xor_bytes = idc.get_bytes(xor_key_bytes_location_2, 35)
        
        decrypt_me = xor_decrypt(get_str_bytes, get_xor_bytes)
        decrypted_str = ''.join(map(chr, decrypt_me))
        print(decrypted_str)
        idc.set_cmt(cur_addr,decrypted_str,0)
