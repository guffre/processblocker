# processblocker
Blocks processes and executables from running on Windows.

# Usage
    (block):   processblocker.exe -a <filename_to_block>
    (unblock): processblocker.exe -[rd] <filename_to_unblock>
    (list): processblocker.exe -l

# How does it work?
The "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" registry key!
This key lets you create subkeys that are executable names. You can then add a REG_SZ value with the name "debugger", and the data contains the file/path of your debugger, in our case "processblocker.exe". This registers "processblocker" as the debugger for that executable.

Normally, the debugger would launch the executable that needs to be debugged. processblocker works by simply not launching it.

# Compilation
    cl processblocker.c
Yup, thats it.

# Installation
You don't really need to install it, but then you will get "file not found" errors cropping up on any processes you've blocked.
Recommend placing in:

    C:\Windows\System32\processblocker.exe
    C:\Windows\SysWOW64\processblocker.exe

This will ensure that logging occurs for both 32-bit and 64-bit executables.

# Why?
Sometimes, there are processes that spinup automatically on Windows that you don't want to run. Maybe its because you have a number of HDDs attached as data storage, and every once in a while some process starts spinning them all up. Maybe these disks are really loud, and you find it annoying that suddenly they start spinning up when you aren't accessing them.

I don't know what sort of process would behave like that, but here's an example of how to use the program:

    processblocker -a compattelrunner.exe
