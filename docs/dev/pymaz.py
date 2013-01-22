#!/usr/bin/env python

import os, sys

ascii_art = ""
ascii_art += "\n\n"                                        
ascii_art += "\t`7MMM.     ,MMF'      db      MMM###AMV "
ascii_art += "\t  MMMb    dPMM       ;MM:     M'   AMV  "
ascii_art += "\t  M YM   ,M MM      ,V^MM.    '   AMV   "
ascii_art += "\t  M  Mb  M' MM     ,M  `MM       AMV    "
ascii_art += "\t  M  YM.P'  MM     AbmmmqMA     AMV   , "
ascii_art += "\t  M  `YM'   MM    A'     VML   AMV   ,M "
ascii_art += "\t.JML. `'  .JMML..AMA.   .AMMA.AMVmmmmMM "
ascii_art += "\t malware analysis zoo => adam m. swanda "
ascii_art += "\t      https://github.com/ohdae/maz      "
ascii_art += "\t           beta version 0.5             "
ascii_art += "\n\n"

help_menu = """

for full documentation, please review the 'MAZ Portal' on the NCSIRT-KB.

        General Commands
      help [command]
   options [mongo/logs/splunk]
    report [pdf/html/txt] [hash/file]  
      iocs [xml/txt] [hash/file]
    submit [hash/file/collection]
    search [hash/name/file]

        Analysis Commands
      load [file/directory]
   analyze [hash/file]
   extract [shellcode/strings]
 blackhole [hash/file]
    cuckoo [hash/file]
    anubis [hash/file]
    vtotal [hash/file]
  threatex [hash/file]
      bit9 [hash/file]
  clusters*

   * this command starts a new interactive shell where you can search for samples based on behavioral traits.
     for example, 'tcp=80 + proc=cmd.exe' will find and display all samples that were found to make a TCP connection
     on port 80 AND executed the cmd.exe process, etc. this feature is experimental and requires some work to get it
     running properly. please view the documentation on how to setup your MAZ clusters.

"""

def start_console():
    print("Welcome to Malware Analysis Zoo!")
    print("type `help` to see all available commands")
    print("or just jump right in and analyze some malware! good luck!\n")
    while True:
        cmd = raw_input("maz >> ")
        if cmd == "help":
            print(help_menu)
        elif cmd == "quit":
            print("[*] saving current database state...")
            print("[*] shutting down the MAZ console.")
            sys.exit(1)
        else:
            pass


print ascii_art
start_console()