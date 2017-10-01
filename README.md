# json_parser


Ablauf: 

1. Alle Reports durchgehen und schauen, welche sample.report.analysis_subject.... elemente es gibt 
2. 



Noch TODO: suche nach Indikatoren implementieren --> abfragen auf Zeichenketten usw 
Ideen für Parser: 

FileCreate --> FileQueryAttribute; Attribute: FILE_ATTRIBUTE_ARCHIVE

Replacing the image of another process (detection evasion or privilege escalation)
vssadmin.exe Delete Shadows /All /Quiet

cryptsp.dll 39% gefährlich 
xpsp2res.dll 63% gefährlich 

IO Status: FILE_SUPERSEDED = Datei soll überschrieben oder erstellt werden (unter filewrite)

ntoskrnl.exe - windows nt operating system kernel

Dateien mit dem Status STATUS_OBJECT_NAME_NOT_FOUND nicht betrachten 

FileSearch betrachten 


svchost -k DcomLaunch damit die cpu leistung geringer wird 

jqs.exe sollte nicht im unterordner des Benutzers vorkommen

compilierter Status sehr alt

wort exe kommt doppelt im namen vor 

wenn lsass.exe gequeriet wird 

lsass.exe wurde erstellt und danach reingeschrieben: create_process; write_mem --> Code Injection oder Privilege Escalation 
nach lsass.exe wurde gesucht und 

kernel32.dll kommt nicht unter c:\windows... vor 

kernel_mode = true?

viele File_Written 

gequeried werden Dateien, ohne Path siehe Sample 40 

wenn Registry mit WINLoGOn verändert wird 

file_queried eine .exe Datei 

windows Dateien werden verändert; Manifestdatetein auch 


HKU\S-1-5-21-1229272821-1563985344-1801674531-1003\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED	 Wert Hidden wird auf 2 gesetzt --> versteckte Dateien werden nicht mehr angezeigt 



komische Dateien/Prozesse: 
gestartet wurden: xpsp2res.dll, cryptsp.dll, ntoskrnl.exe, jqs.exe(vor allem, wenn sie aus unterordner des Benutzers gestartet wird)
im Namen kommt doppelt .exe vor, viele Leerzeichen 
Dateien von Windows werden nicht mit dem richtigen Pfad gestartet

privilege escalation: 
vssadmin.exe Delete Shadows /All /Quiet Befehl; 

ransom: 
1. in viele Dateien wurde geschrieben 


sonstiges: 
nach besonderen Dateien wurde gesucht: lsass.exe, cmd.exe usw 
compilierter status sehr alt 
bekannter Prozess wird erstellt und dann wurde reingeschrieben (Code Injection)
es wird nach vielen Dateien gesucht, die keinen Path haben 
Windows Dateien werden verändert; Manifestdatetein auch 


veränderte Registries: 
WINLOGON
RUN
RUNONCE
MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED Wert: Hidden: versteckte Dateien werden nicht mehr angezeigt 

Indikatoren: 

1. in verdächtig viele Dateien wurde geschrieben 
2. verdächtige registries wurden geöffnet
3. deleted Shadows with vssadmin.exe Delete Shadows /All /Quiet
4. compilierter zeitpunkt sehr alt
5. komische Prozesse wurden gestartetet: xpsp2res.dll, cryptsp.dll, ntoskrnl.exe, jqs.exe
6. .exe kommt doppelt vor; name hat viele Leerzeichen 
