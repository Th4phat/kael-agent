rule Anti_Debug_Techniques {
    meta:
        description = "Detects common anti-debugging techniques"
        author = "Kael"
        severity = "medium"
    strings:
        $isdebuggerpresent = "IsDebuggerPresent" nocase
        $checkremotedebuggerpresent = "CheckRemoteDebuggerPresent" nocase
        $ntqueryinformationprocess = "NtQueryInformationProcess" nocase
        $outputdebugstring = "OutputDebugStringA" nocase
        $ptrace = "ptrace" nocase
        $int3 = { CC }
        $int2d = { CD 2D }
    condition:
        any of them
}

rule Anti_VM_Techniques {
    meta:
        description = "Detects VM detection techniques"
        author = "Kael"
        severity = "medium"
    strings:
        $vmware1 = "VMware" nocase
        $vmware2 = "VMXh"
        $virtualbox = "VirtualBox" nocase
        $vbox = "VBOX" nocase
        $qemu = "QEMU" nocase
        $xen = "XenVMM" nocase
        $hyperv = "Microsoft Hv" nocase
        $redpill = { 0F 01 0D 00 00 00 00 }
    condition:
        2 of them
}

rule Code_Injection {
    meta:
        description = "Detects code injection techniques"
        author = "Kael"
        severity = "high"
    strings:
        $createremotethread = "CreateRemoteThread" nocase
        $writeprocessmemory = "WriteProcessMemory" nocase
        $virtualalloc = "VirtualAllocEx" nocase
        $ntunmapviewofsection = "NtUnmapViewOfSection" nocase
        $setthreadcontext = "SetThreadContext" nocase
        $process32first = "Process32First" nocase
        $process32next = "Process32Next" nocase
    condition:
        3 of them
}

rule Persistence_Registry {
    meta:
        description = "Detects registry persistence mechanisms"
        author = "Kael"
        severity = "high"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $winlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $startup = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" nocase
        $regsetvalue = "RegSetValueEx" nocase
        $regcreatekey = "RegCreateKeyEx" nocase
    condition:
        2 of them
}
