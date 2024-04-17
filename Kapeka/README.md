# Kapeka
These artifacts are related to WithSecure’s investigation on Kapeka.

A report with detailed analysis titled "Kapeka: A novel backdoor spotted in Eastern Europe" is available on WithSecure Labs Blog: https://labs.withsecure.com/publications/kapeka

List of artifacts:
* `iocs.csv` is a list of indicators of compromise (IOCs) for Kapeka in CSV format.
* `kapeka_backdoor.yar` is a YARA rule that can detect Kapeka backdoor samples.
* `kapeka_extract_backdoor.py` is a Python script to extract and decrypt the backdoor binary from the dropper’s resource section. Usage explained below.
* `kapeka_http_handler.py` is a script to decrypt and emulate Kapeka’s network communication. This has been implemented as a custom HTTP handler for [fakenet](https://github.com/mandiant/flare-fakenet-ng). Usage explained below.
* `kapeka_extract_config.py` is a script to extract Kapeka’s configuration from either registry or embedded within the backdoor binary. Usage explained below.

## Usage
### kapeka_extract_backdoor.py
This script will extract and decrypt backdoor binaries found in Kapeka's dropper. It will save the decrypted resources into the current working directory. This script can only be executed on Windows.

Requires Python >= 3.7.8 and Python library: `pycryptodome`

Example of usage:
`$ python kapeka_extract_backdoor.py dropper.exe`

### kapeka_extract_config.py
This script will extract Kapeka's configuration from either local registry or embedded within the backdoor binary. To extract from local registry, this script needs to be executed on a machine infected with Kapeka.

Requires Python >= 3.7.8 and Python library: `pycryptodome`

Example of usage (to extract from local registry):
`$ python kapeka_extract_config.py`

Example of usage (to extract from binary)
`$ python kapeka_extract_config.py backdoor.exe`

### kapeka_http_handler.py
This script is a custom HTTP handler for Kapeka's network communication. It can be used to emulate Kapeka's C2 responses and dump its requests. This has been implemented and tested with [fakenet](https://github.com/mandiant/flare-fakenet-ng).

To get started you need to:
* Generate an RSA-2048 key pair.
* Replace the private key in the script with the generated private key.
* Replace the public key in the Kapeka backdoor you want to analyze with the generated public key.
* Configure fakenet to use the provided script to handle HTTP traffic for Kapeka C2 addresses.
