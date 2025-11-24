rule tanglecrypt
{
    meta:
        author="WithSecure"
        description="Detects samples packed with TangleCrypt"
        date="2025-11-25"
        version="1.0"
        reference="https://labs.withsecure.com/publications/tanglecrypt"
        hash1="2936f5f3ff24f5bb42eace4ad2d64989b19dc6cd75d8f4ee83496ee6bdf169f6"
        hash2="fb3fc93dc627c7dfd8d95c1d66c2cb66caac92783b6d6eb33ac5b91647871ae6"
    strings:
        // "Can't call WinAPI function"
        $str1 = { 43 61 6E 27 74 20 63 61 6C 6C 20 57 69 6E 41 50 49 20 66 75 6E 63 74 69 6F 6E }
        // mov r8d, 0x8D7 -- (...) -- call <memcpy>
        $opc_x64 = { 41 B8 D7 08 00 00 [0-10] ( E8 | FF 15 ) }
        // push 0x8D7 -- (...) -- call <memcpy>
        $opc_x86 = { 68 D7 08 00 00 [0-10] ( E8 | FF 15 ) }
    condition:
        // MZ
        uint16(0) == 0x5A4D
        // PE
        and (uint32(uint32(0x3C)) == 0x00004550)
        // strings
        and all of ($str*)
        // opcodes
        and (#opc_x64 > 50 or #opc_x86 > 50)
}
