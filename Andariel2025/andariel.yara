import "pe"
import "string"
import "math"
rule Andariel_TomCryptor
{
  meta:
      author = "WithSecure"
      description = "Detects TomCryptor samples based on file characteristics"
  condition:
    pe.is_pe
    and pe.number_of_resources == 2
    // Payload should be greater than ~20kb
    and pe.resources[0].length > 20000
    // High-entropy resource
    and math.entropy(pe.resources[0].offset, pe.resources[0].length) > 7
    // Resource name is 4-digit number
    and string.length(pe.resources[0].name_string) == 8
    and pe.resources[0].name_string matches /[0-9]\x00[0-9]\x00[0-9]\x00[0-9]\x00/
    // Imports associated to MFC application
    and pe.number_of_imports > 16
    and pe.number_of_imports < 19
    and pe.imports("ADVAPI32.dll")
    and pe.imports("COMCTL32.dll")
    and pe.imports("GDI32.dll")
    and pe.imports("IMM32.dll")
    and pe.imports("KERNEL32.dll")
    and pe.imports("MSIMG32.dll")
    and pe.imports("OLEACC.dll")
    and pe.imports("OLEAUT32.dll")
    and pe.imports("SHELL32.dll")
    and pe.imports("SHLWAPI.dll")
    and pe.imports("USER32.dll")
    and pe.imports("UxTheme.dll")
    and pe.imports("WINMM.dll")
    and pe.imports("WINSPOOL.DRV")
    and pe.imports("gdiplus.dll")
    and pe.imports("ole32.dll")
    and pe.imports("oledlg.dll")
}
rule Andariel_UnderCrypt
{
  meta:
      author = "WithSecure"
      description = "Detects UnderCrypt samples based on shared code portions"
  strings:
    $1 = {C0746F4C8BDE498D1C024D2B5D304C3BD3735FBF00F0000041BE00A0000041833A00744E458B42044D8D4A084983E80849D1E84585C0742E90410FB71141FFC8}
    $2 = {00448B461C448B4E244C03C2448B56204C03CA4C03D2F7C50000FFFF752B8B4E100FB7D53BD17213034E143BD1730C0FB7C5418B1C804903DBEB6433C04881C4}
    $6 = {119C4000C04FA30A3E23672FCB3AABD2119C4000C04FA30A3E9EDB32D3B3B925418207A14884F532168D1880928E0E6748B30C7FA83884E8DED2D139BD2FBA6A4889B0B4B0CB466891DC96F605292B6336AD8BC4389CF2A7132205931904000000}
    $7 = {647265488D5424204863403C448BC366C744242C7373885C242E428B8C10880000004903CA448B49208B79244D03CA8B711C4903FA448B59144903F24585DB7441418B01B1474903C23A08750E0FB64A0148FFC248FFC084C975EE0FB608380A741341FFC0488D5424204983C104453BC3}
    $8 = {4C8BD0C745E04765745033D2C745E4726F63418BFA8855EE4863403C448BC2C745E864647265488D55E066C745EC7373428B8C10880000004903CA448B4920448B69244D03CA8B411C4D03EA448B59144903C2488945484585DB744C660F1F440000418B01B1474903C23A08750E0FB64A0148FFC248FF}
  condition:
    any of them
}
rule Andariel_UnderCrypt_VersionInfo
{
  meta:
      author = "WithSecure"
      description = "Detects UnderCrypt samples based on version info"
  condition:
    (
        pe.version_info["ProductName"] == "Microsoft@Windows@OperatingSystem"
        )
    or (
        pe.version_info["InternalName"] contains "_crypted."
        and pe.version_info["FileVersion"] contains "10.0.19041.1"
        )
}
rule Andariel_StarShellRAT
{
  meta:
      author = "WithSecure"
      description = "Detects StarshellRAT samples"
  strings:
    $str1 = "StarShell" ascii
    $str2 = "ReadRlt" ascii
    $str3 = "SendRlt" ascii
    $str4 = "ProcessShell" ascii
    $str5 = "Screan ok" wide
    $str6 = "<==>" wide
    $str7 = "\\r\\nStarted..." wide
    $str8 = "\\r\\nDownload End." wide
    $str9 = "\\r\\nupload end" wide
  condition:
    pe.is_pe and 3 of them
}
rule Andariel_GopherRAT
{
  meta:
      author = "WithSecure"
      description = "Detects GopherRAT samples"
  strings:
    $cmdName1 = "GetMACHashID"
    $cmdName2 = "startHeartbeat"
    $cmdName3 = "encodeTo949"
    $cmdName4 = "xorDecrypt"
    $cmdName5 = "StartShell"
    $cmdName6 = "getLogicalDrives"
    $cmdName7 = "sendSocksCommand"
    $xorKey = {357095A221F033AC}
  condition:
    pe.is_pe and (
        3 of ($cmdName*)
        or $xorKey
    )
}
rule Andariel_PortScanner_VersionInfo
{
  meta:
      author = "WithSecure"
      description = "Detects custom port scanner based on file version info"
  condition:
        pe.version_info["InternalName"] == "PortScan.exe"
        and pe.version_info["ProductName"] == "Chrome"
}
rule Andariel_EDR_KILLER_Script {
  meta:
      author = "WithSecure"
      description = "Detects strings found in EDR killer batch script"
  strings:
    $a1 = "PageSvc" ascii
    $a2 = "page.sys" ascii
  condition:
    all of them
}
rule Andariel_JelusRAT_PDB
{
    meta:
        author = "WithSecure"
        description = "Detects JelusRAT packer and payload samples via PDB path"
    strings:
        $str_pdb = /jelus *rat[\x20-\x7F]{0,100}\.pdb\x00/ nocase
    condition:
        // max 16 MB
        filesize <= 16MB
        // MZ
        and uint16(0) == 0x5A4D
        // PE
        and (uint32(uint32(0x3C)) == 0x00004550)
        // PDB path
        and all of them
}
rule Andariel_JelusRAT_Plugin
{
    meta:
        author = "WithSecure"
        description = "Detects JelusRAT plugins"
    condition:
            pe.exports("testPlugin")
        and pe.exports("beginPlugin")
        and pe.exports("endPlugin")
        and pe.exports("processCommand")
}
