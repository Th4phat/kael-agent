rule UPX_Packer {
    meta:
        description = "Detects UPX packed executables"
        author = "Kael"
        severity = "medium"
    strings:
        $upx1 = "UPX0" nocase
        $upx2 = "UPX1" nocase
        $upx3 = "UPX!" nocase
        $upx_sig = { 55 50 58 }
    condition:
        any of them
}

rule MPRESS_Packer {
    meta:
        description = "Detects MPRESS packed executables"
        author = "Kael"
        severity = "medium"
    strings:
        $mpress1 = ".MPRESS1"
        $mpress2 = ".MPRESS2"
        $mpress_sig = "MPRESS"
    condition:
        any of them
}

rule Themida_Packer {
    meta:
        description = "Detects Themida/WinLicense packed executables"
        author = "Kael"
        severity = "high"
    strings:
        $themida1 = ".themida"
        $themida2 = "Themida"
        $winlicense = "WinLicense"
        $oreans = "Oreans"
    condition:
        any of them
}

rule VMProtect_Packer {
    meta:
        description = "Detects VMProtect packed executables"
        author = "Kael"
        severity = "high"
    strings:
        $vmp1 = ".vmp0"
        $vmp2 = ".vmp1"
        $vmp3 = "VMProtect"
    condition:
        any of them
}

rule ASPack_Packer {
    meta:
        description = "Detects ASPack packed executables"
        author = "Kael"
        severity = "medium"
    strings:
        $aspack1 = ".aspack"
        $aspack2 = ".adata"
        $aspack3 = "ASPack"
    condition:
        any of them
}

rule PECompact_Packer {
    meta:
        description = "Detects PECompact packed executables"
        author = "Kael"
        severity = "medium"
    strings:
        $pec1 = "PECompact"
        $pec2 = ".pec1"
        $pec3 = ".pec2"
    condition:
        any of them
}

rule Generic_Packer_Indicators {
    meta:
        description = "Generic packer detection based on common indicators"
        author = "Kael"
        severity = "low"
    strings:
        $stub = ".stub"
        $packed = ".packed"
        $protect = ".protect"
        $enigma = ".enigma"
    condition:
        any of them
}
