/*
   YARA Rule Set
   Author: Arda Büyükkaya
   Date: 2022-08-06
   Identifier: APT Academic
*/

/* Rule Set ----------------------------------------------------------------- */

rule Birlestirilmis_GORUSLER {
   meta:
      description = "Academic APT - file Birlestirilmis_GORUSLER.doc"
      author = "Arda Büyükkaya"
      date = "2022-08-06"
      hash1 = "6d0e053abe4f93653bf912b09944f862898937b6a789df255778b7bdaad42920"
   strings:
      $x1 = "6AAAAABZSYnISIHBCAYAALpA2CThSYHACMAEAEG5AAAAAFZIieZIg+TwSIPsMMdEJCAAAAAA6AUAAABIifRew0iLxESJSCBMiUAYiVAQU1VWV0FUQVVBVkFXSIPseINg" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule KGB_Numaralari_ve_Gecerlilik_Tarihleri {
   meta:
      description = "Academic APT - file KGB Numaralari ve Gecerlilik Tarihleri.xlsx"
      author = "Arda Büyükkaya"
      date = "2022-08-06"
      hash1 = "a88af5d0ff6ec1a72a41977e5f610c153dfbd75ab70d054ca9101443c3fb62e2"
   strings:
      $s1 = "r:\"y_dl" fullword ascii
      $s2 = "MWrr}z-" fullword ascii
      $s3 = "RSLX\"7" fullword ascii
      $s4 = "BJlkVRn-" fullword ascii
      $s5 = "joCkYvOfL_" fullword ascii
      $s6 = "wzOB+V=4" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 300KB and
      8 of them
}

rule FileSyncShell64 {
   meta:
      description = "Academic APT - file FileSyncShell64.dll"
      author = "Arda Büyükkaya"
      date = "2022-08-06"
      hash1 = "7327d83e087384e79c91d4fb3e209f832d5b2d47edad1a591f407675493ecd18"
   strings:
      $s1 = "FileSyncShell64.dll" fullword ascii
      $s2 = "File Sync Shell Library (x64)" fullword wide
      $s3 = "FileSyncShell64" fullword wide
      $s4 = "VtNwFNe" fullword ascii
      $s5 = "qUXt{f4" fullword ascii
      $s6 = "ezVS.\\" fullword ascii
      $s7 = "8uSMMx+bk`" fullword ascii
      $s8 = "idlt$\\" fullword ascii
      $s9 = "qmgW\"7" fullword ascii
      $s10 = "CVIn5b4" fullword ascii
      $s11 = "BtggGjg" fullword ascii
      $s12 = "qYzv{f4" fullword ascii
      $s13 = "\\I[6TQ" fullword ascii
      $s14 = "C+yV+\\^" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}



rule Dropout_APT{
   meta:
      description = "Academic APT - from files Birlestirilmis_GORUSLER.doc, MURENPRVZ-KYP-03-EK3-YKS (Yazilim Konfigurasyon Sureci).doc, MURENPRVZ-KYP-03-EK5-PMF (Platforma Mudahale Formu).doc, MÜRENPRVZ-STB-XX-XX (Surum Tanimlama Belgesi).doc"
      author = "Arda Büyükkaya"
      date = "2022-08-06"
      hash1 = "6d0e053abe4f93653bf912b09944f862898937b6a789df255778b7bdaad42920"
      hash2 = "217709cbc11d5f7f73bd23de4ffad455710001519a0f0f2f6d8e6f3f5f79cfed"
      hash3 = "2941f19f7319b92ba58b3247374189fa8f68f9db06b5d81f0ffb8551da07a1bc"
      hash4 = "65ed7010a294b72c9418dd0514f99f17fa57ceb87bf4f7622cf27c2a7ba76661"
   strings:
      $s1 = "WScript.Shell" fullword ascii
      $s2 = "ExecuteY" fullword ascii
      $s3 = "tion.Scr@eenUpd" fullword ascii
      $s4 = " INCLUDEPICTURE http://tbkdock.esxi.cdd/ping.img \\* MERGEFORMAT " fullword wide
      $s5 = "RegKeyExists-" fullword ascii
      $s6 = "Public Sub SayHello()" fullword ascii
      $s7 = "myRegKeye" fullword ascii
      $s8 = "LAPPDATAB\"" fullword ascii
      $s9 = "temp2MC" fullword ascii
      $s10 = "\"\\Temp\" " fullword ascii
      $s11 = "Microsoft.XMLHTTP" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
