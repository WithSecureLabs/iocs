import "pe"
rule kapeka_backdoor
{
  meta:
        author="WithSecure"
        description="Detects Kapeka backdoor based on common strings."
        date="2024-04-17"
        version="1.0"
        reference="https://labs.withsecure.com/publications/kapeka"
        hash1="97e0e161d673925e42cdf04763e7eaa53035338b"
        hash2="9bbde40cab30916b42e59208fbcc09affef525c1"
        hash3="6c3441b5a4d3d39e9695d176b0e83a2c55fe5b4e"
  strings:
    $a = "Azbi3l1xIgcRzTsOHopgrwUdJUMWpOFt" ascii
    $b = "PID : " wide
    $c = "ExitCode : " wide
    $d = "1: " wide
    $e = "2: " wide
  condition:
    pe.is_dll() and filesize > 50000 and filesize < 500000 and 4 of them 
}