import idc, idautils, idaapi

# reference https://kienmanowar.wordpress.com/2022/12/19/z2abimonthly-malware-challege-emotet-back-from-the-dead/

decrypt_fn_addr = 0x180025C58

for addr in idautils.CodeRefsTo(decrypt_fn_addr, 1): 
    # go into the the string building and decryption wrap function
    decrypt_str_addr = idaapi.get_func(addr).start_ea
    #get a function name
    decrypt_fn_name = idc.get_func_name(decrypt_str_addr)
    
    # building out the Appcall proto
    decrypt_fn_proto = "wchar_t * __fastcall {:s}();".format(decrypt_fn_name)
    decrypt_fn_appcall = idaapi.Appcall.proto(decrypt_str_addr, decrypt_fn_proto)
    
    # calling the decryption function
    decrypt_string = decrypt_fn_appcall()
    cleaned_str = decrypt_string.replace(b'\x00', b'')
    #convert from bytes to string
    cleaned_str = cleaned_str.decode('latin-1')
    
    # setting the comments
    idc.set_cmt(addr, cleaned_str, 0)
    idc.set_func_cmt(decrypt_str_addr, cleaned_str, 1)
    
