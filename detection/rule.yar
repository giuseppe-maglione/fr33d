rule fr33d_detection {
    meta:
        description = "Detection rule for fr33d malware"

    strings:
        // magic header
        $magic = { 4D 5A }

        // very specific
        $url = "http://192.168.122.235:8080/OneDrive_Component.bin"
        $mutex = "Global\\OneDriveSyncMutex"

        // specific strings
        $filename = "OneDriveUpdate.exe"
        $path = "OneDrive_Update"
        $registry_path = "Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell"

        // common strings
        $user_agent = "Mozilla/5.0"
        $reg_value = "Bypass"
        $reg_key = "ExecutionPolicy"

    condition:
        $magic at 0 and 
        (
            (1 of ($url, $mutex)) 
            or 
            (2 of ($filename, $path, $registry_path) and 2 of ($user_agent, $reg_value, $reg_key))
        )
}
