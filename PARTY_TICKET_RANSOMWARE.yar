rule PARTY_TICKET_RANSOMWARE {
    meta:
      description = "PartyTicket Golang Ransomware - associated with HermeticWiper campaign"
      author = "Arda Büyükkaya"
      reference = ""
      date = "2022-02-27"
      hash1 = "4dc13bb83a16d4ff9865a51b3e4d24112327c526c1392e14d56f20d6f4eaf382"
    strings:
        $string1 = "/403forBiden/" wide ascii nocase
        $string2 = "/wHiteHousE/" wide ascii 
        $string3 = "vote_result." wide ascii
        $string4 = "partyTicket." wide ascii
        $buildid1 = "Go build ID: \"qb0H7AdWAYDzfMA1J80B/nJ9FF8fupJl4qnE4WvA5/PWkwEJfKUrRbYN59_Jba/2o0VIyvqINFbLsDsFyL2\"" wide ascii
        $project1 = "C:/projects/403forBiden/wHiteHousE/" wide ascii
    condition:
      uint16(0) == 0x5A4D and
      (2 of ($string*) or 
        any of ($buildid*) or 
        any of ($project*))
}