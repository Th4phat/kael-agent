rule AES_Constants {
    meta:
        description = "Detects AES encryption constants (S-box)"
        author = "Kael"
        severity = "info"
    strings:
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $aes_te0 = { C6 63 63 A5 F8 7C 7C 84 }
        $aes_td0 = { 51 F4 A7 50 7E 41 65 53 }
    condition:
        any of them
}

rule RSA_Constants {
    meta:
        description = "Detects RSA cryptographic constants"
        author = "Kael"
        severity = "info"
    strings:
        $rsa_exp = { 01 00 01 }
        $rsa_lib1 = "CryptEncrypt" nocase
        $rsa_lib2 = "CryptDecrypt" nocase
        $rsa_lib3 = "CryptGenKey" nocase
    condition:
        any of them
}

rule Base64_Table {
    meta:
        description = "Detects Base64 encoding table"
        author = "Kael"
        severity = "info"
    strings:
        $base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $base64_url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    condition:
        any of them
}

rule XOR_Loop {
    meta:
        description = "Detects XOR decryption loops"
        author = "Kael"
        severity = "medium"
    strings:
        $xor_pattern1 = { 30 ?? ?? 40 3D ?? ?? ?? ?? 7C }
        $xor_pattern2 = { 80 ?? ?? 48 FF ?? 75 }
        $xor_pattern3 = { 34 ?? 88 ?? E2 }
    condition:
        any of them
}

rule RC4_Constants {
    meta:
        description = "Detects RC4 stream cipher constants"
        author = "Kael"
        severity = "info"
    strings:
        $rc4_init = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 }
    condition:
        $rc4_init
}
