# tesla_yara
Yara rule for detecting teslacrypt version 3.0.1 and similar samples using the same TTP techniques.
The rule has been designed to detect the unpacked version of the malware- therefore the rule will not work on the packed version MSUpdate.exe.
Comments for each line are either above, or at the end of the line.
Comments include
- the text that is encoded in UTF-16
- labels for the TTP relating to each condition


Additionally I have included the small python script used to encode plaintext to UTF-16 little endian format for use in the yara rule
