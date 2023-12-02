rule teslacrypt 

{

	meta:

		description = "Detecting the string patterns associated with TTPs relating to teslacrypt"

		author = "2103794"



	strings:

		$magic_bytes = {4d 5a} // ensuring the file is an executable

		$user_agent = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0)"	

		$MIME = "application/x-www-form-urlencoded"

			// %s\\system32\\cmd.exe

		$persistence1 = { 25 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 }

			//  /c start \"\" \" 

		$persistence2 = { 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 }

			// Microsoft\\Windows\\CurrentVersion\\Run

		$persistence_location = { 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 }

			// EnableLinkedConnections

		$linked_connections = { 45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 69 00 6e 00 6b 00 65 00 64 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 73 00 }

		$linked_connections_location = "Microsoft\\Windows\\CurrentVersion\\Policies\\System"

		$recovery_caps = { 52 00 45 00 43 00 4f 00 56 00 45 00 52 00 59 00 } // RECOVERY

		$recover_lowercase = { 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 } // recover

		$wide_string_zzzsys = { 78 00 78 00 78 00 73 00 79 00 73 00} // zzzsys

		$mp3_extension = { 2e 00 6d 00 70 00 33 00 } // .mp3

		$onion = ".onion" // for tor links

			// shadowcopy deletion

		$shadowcopy = "shadowcopy"

		$delete = "delete"

		$interactive = "active"

			// Libraries used for malicious behaviour

		$kernel32 = "kernel32.dll"

		$advapi32 = "advapi32.dll"

		$ntdll = "ntdll.dll"

		$ws2_32 = "ws2_32.dll"

		$wininet = "wininet.dll"

	

	condition:

		// Checking that the file is a windows executable and includes the listed dlls

		$magic_bytes at 0 and ($kernel32 and $advapi32 and $ntdll and $ws2_32 and $wininet) and 

		(
			// Checking for strings relating to communication method, recovery/ransom note, encryption file extension and .onion for bitcoin TOR links

			2 of (

				$user_agent, 

				$MIME,

				$recovery_caps,

				$recover_lowercase,

				$mp3_extension,

				$onion

				)

			and (

				$persistence_location and ($persistence1 or $persistence2) //persistence TTP

				or ($wide_string_zzzsys) //checking for victimID (instID) TTP

				or ($linked_connections and $linked_connections_location) //enabling linked connections TTP

				or ($shadowcopy and $delete and $interactive) //shadowcopy TTP

				)				  

		)

}
