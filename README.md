# DLL-for-hook-WinAPI-functions

Dll MITRE ATT&CK is an executable DLL that is injected into launched processes to intercept the call of dangerous functions, blocking the call of dangerous operations (based on MITER ATT & CK) based on the signature sequence of function calls. If there is a match with the signature, then the function call is blocked, returning NULL values; otherwise, a pointer to the required called function is returned. Functions are intercepted using Microsoft Detours. This dll is a pipe client that sends messages to a pipe server named \\. \ Pipe \ WINAPIDLL.

Detours is a library for instrumentation of arbitrary functions on Win32 Windows-compatible processors. Detours intercepts Win32 functions by rewriting in-memory code for target functions. The Detours package also contains utilities for attaching arbitrary DLLs and data segments (called payloads) to any Win32 binary.

The following MITER ATT & CK attack techniques were taken as an example:

• Screensaver,

• Security Support Provider,

• AppInit DLLs,

• Astaroth,

• Netsh Helper DLL.
