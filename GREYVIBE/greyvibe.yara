rule DAYLIGHT
{
  meta:
    author = "WithSecure"
    description = "Detects common strings found across samples obfuscated with DAYLIGHT"
  strings:
    $a = "$encryptedstream, $keystream" nocase ascii wide
    $b = "Daylight savings time is active" ascii wide
  condition:
    any of them
}

rule TEASOUP
{
  meta:
    author = "WithSecure"
    description = "Detects common strings found across samples obfuscated with TEASOUP"
  strings:
    $a = "s += String.fromCharCode(charCode)" ascii wide
    $b = "var ts = arr[i]" ascii wide
    $c = "System Maintenance Script" ascii wide
  condition:
    2 of ($*)
}

rule LOOKVALPS
{
  meta:
    author = "WithSecure"
    description = "Detects common strings found across samples obfuscated with LOOKVALPS"
  strings:
    $a = "currentValue = $LookupTable" ascii wide
    $b = "foreach($b in $data){$d+=[char]($b -bxor $key)}" ascii wide
  condition:
    any of them
}

rule LOOKVALJS
{
  meta:
    author = "WithSecure"
    description = "Detects a common string found across samples obfuscated with LOOKVALJS"
  strings:
    $a = "currentValue = lookupTable" ascii wide
  condition:
    all of them
}

rule GREYVIBE_JSLOADER_1
{
  meta:
    author = "WithSecure"
    description = "Detects common strings found across one of GREYVIBE's loaders (observed across PrincessClub and PhantomMail campaigns)"
  strings:
    $a = "wmizzzz"
    $b = "runzzzz"
  condition:
    all of them
}

rule GREYVIBE_JSLOADER_2
{
  meta:
    author = "WithSecure"
    description = "Detects common strings found across one of GREYVIBE's loaders (observed in PhantomMail campaign)"
  strings:
    $a = "// String Reconstruction"
    $b = "Math.cos"
    $c = "Math.sin"
    $d = ".join(\"\")"
  condition:
    all of them
}

rule PhantomRelay_Fingerprint
{
  meta:
    author = "WithSecure"
    description = "Detects PhantomRelay's fingerprinting script"
    target_entity = "file"
  strings:
        $a1 = "$env:COMPUTERNAME"
        $a2 = "$env:USERNAME"
        $a3 = "$PID"
        $a4 = "Win32_Computer"
        $user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/534.36 (KHTML, like Gecko) Chrome/95.4.4476.124 Safari/537.36"
  condition:
    all of them
}

rule GREYVIBE_PhantomRelay_Watchdog
{
  meta:
    author = "WithSecure"
    description = "Detects GREYVIBE's watchdog script for PhantomRelay"
  strings:
        $a1 = "--headless"
        $a2 = "/watchdog"
        $a3 = "Register-ScheduledTask"
        $a4 = "DownloadFile"
  condition:
    filesize < 50KB and all of them
}

rule LegionRelay_Client
{
  meta:
    author = "WithSecure"
    description = "Detects LegionRelay client script"
  strings:
        $a1 = "powershell_ise"
        $a2 = "pwsh"
        $a3 = "/status"
        $a4 = "/commands?client_id="
        $a5 = "[^\\w\\-]"
        $a6 = "client_config.json"
  condition:
    all of them
}

rule FallSpy
{
  meta:
    author = "WithSecure"
    description = "Detects FallSpy Android malware"
  strings:
    $a = "DataCollectorWork" fullword
    $b = "UpdateChecker" fullword
    $c = "/check_update?version="
    $e = "&call_logs=" fullword
    $f = "&sim_numbers=" fullword
    $g = "&wifi_ssid=" fullword
    $h = "Public IP: " fullword
    $i = "uploaded_hashes" fullword
    $n = "Android ID: " fullword
    $o = "Call Logs: " fullword
  condition:
    4 of them
}

rule PhantomRelay_Client
{
  meta:
    author = "WithSecure"
    description = "Detects PhantomRelay client script"
  strings:
    $a = ".idc"
    $b = ".cmd"
    $c = ".psh"
    $d = "WebSockets.ClientWebSocket"
  condition:
    filesize < 100KB and all of them
}