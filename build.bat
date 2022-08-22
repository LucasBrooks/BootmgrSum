@cl /nologo /c /D "_UNICODE" /D "UNICODE" main.cpp
@link /NOLOGO main.obj imagehlp.lib shell32.lib kernel32.lib /ENTRY:WinStart /SUBSYSTEM:CONSOLE
