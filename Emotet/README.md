Emotet string decryption and API/DLL resolver based on the calculated hash
Note: in order to successfully run emotet_dll_resolver.py, you need to set the correct function type definition in IDA ("Y"), for example: __int64 __fastcall sub_18000F174(int a1, int a2), otherwise it will return "NoneType" error
