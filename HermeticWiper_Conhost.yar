/*
   YARA Rule Set
   Author: Arda Büyükkaya
   Date: 2022-02-27
   Identifier: HermeticWiper
   Reference: 
*/

/* Rule Set ----------------------------------------------------------------- */

rule HermeticWiper_Conhost {
   meta:
      description = "HermeticWiper - file Conhost.exe"
      author = "Arda Büyükkaya"
      reference = ""
      date = "2022-02-27"
      hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
   strings:
      $s1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" fullword wide
      $s2 = "PhysicalDrive%u" wide ascii nocase
      $s3 = "\\\\?\\C:\\Documents and Settings" fullword wide
      $s4 = "C:\\System Volume Information" fullword wide
      $s5 = "tdrv.pdb" fullword ascii
      $s6 = "DRV_XP_X64" wide ascii nocase
      $s7 = ".com/r" fullword ascii
      $s8 = "EPMNTDRV\\%u" fullword wide
      $s9 = "runtime " fullword ascii
      $s10 = "PerfLogs" fullword wide
      $s11 = "accessdr" fullword ascii
      $s12 = "ccessdri" fullword ascii
      $s13 = "ndiskacc" fullword ascii
      $s14 = "jectarea" fullword ascii
      $s15 = "eference" fullword ascii
      $s16 = "chronous" fullword ascii
      $s17 = "windiska" fullword ascii
      $s18 = "essdrive" fullword ascii
      $s19 = "ojectare" fullword ascii
      $s20 = "h:\\epm2" fullword ascii
	  $cert1 = "Hermetica Digital Ltd" wide ascii nocase
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

