#define _CRT_SECURE_NO_WARNINGS
#include <string>
#include <tchar.h>
#include <stdio.h>
#include <Windows.h>

#include <Lm.h>
#include <time.h>
#include <Dsgetdc.h>
#include <WinInet.h>
#include <detours.h>

#include <fstream>

#undef BOOLAPI
#undef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#undef SECURITY_FLAG_IGNORE_CERT_CN_INVALID

#define URL_COMPONENTS URL_COMPONENTS_ANOTHER
#define URL_COMPONENTSA URL_COMPONENTSA_ANOTHER
#define URL_COMPONENTSW URL_COMPONENTSW_ANOTHER
#define LPURL_COMPONENTS LPURL_COMPONENTS_ANOTHER
#define LPURL_COMPONENTSA LPURL_COMPONENTS_ANOTHER
#define LPURL_COMPONENTSW LPURL_COMPONENTS_ANOTHER
#define INTERNET_SCHEME INTERNET_SCHEME_ANOTHER
#define LPINTERNET_SCHEME LPINTERNET_SCHEME_ANOTHER
#define HTTP_VERSION_INFO HTTP_VERSION_INFO_ANOTHER
#define LPHTTP_VERSION_INFO LPHTTP_VERSION_INFO_ANOTHER

#include <winhttp.h>

#undef URL_COMPONENTS
#undef URL_COMPONENTSA
#undef URL_COMPONENTSW
#undef LPURL_COMPONENTS
#undef LPURL_COMPONENTSA
#undef LPURL_COMPONENTSW
#undef INTERNET_SCHEME
#undef LPINTERNET_SCHEME
#undef HTTP_VERSION_INFO
#undef LPHTTP_VERSION_INFO


#pragma comment(lib, "netapi32.lib")

using namespace std;
#define _CRT_SECURE_NO_WARNINGS

string get_time();
void log(const char* msg);
void send_message(string msg, int choice);
char* wchar_to_char(const wchar_t* pwchar);
char* get_current_process();

HMODULE(WINAPI* pLoadLibraryA)
(LPCSTR lpLibFileName)
= LoadLibraryA;

HMODULE(WINAPI* pLoadLibraryW)
(LPCWSTR lpLibFileName)
= LoadLibraryW;

LSTATUS(WINAPI* pRegCreateKeyA)
(HKEY   hKey, LPCSTR lpSubKey, PHKEY  phkResult)
= RegCreateKeyA;

LSTATUS(WINAPI* pRegCreateKeyW)
(HKEY   hKey, LPCWSTR lpSubKey, PHKEY  phkResult)
= RegCreateKeyW;

HANDLE(WINAPI* pCreateFileA)
(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
= CreateFileA;

/*
HANDLE(WINAPI* pCreateFileW)
(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
= CreateFileW;
*/

BOOL(WINAPI* pCreateProcessA)
(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
= CreateProcessA;

BOOL(WINAPI* pCreateProcessW)
(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
= CreateProcessW;

//////////////////////////////////////////////////////////////////////////////////////////////////////////

HMODULE WINAPI MyLoadLibraryA(
	LPCSTR lpLibFileName
)
{
	HMODULE res;

	log("Checking LoadLibraryA...");
	if (!strcmp(lpLibFileName, "C:\\Windows\\Syswow64\\userinit.exe"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Astaroth. T1093' ! Ñreating a dangerous file: ";
		msg += lpLibFileName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling LoadLibraryA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpLibFileName, "C:\\Windows\\System32\\userinit.exe"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Astaroth. T1093' ! Ñreating a dangerous file: ";
		msg += lpLibFileName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling LoadLibraryA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		string msg = "Call LoadLibraryA. LibName: ";
		msg += lpLibFileName;
		msg += ". ProcessName: ";
		msg += get_current_process();

		send_message(msg, 0);
		log(msg.c_str());
		return pLoadLibraryA(lpLibFileName);
	}
}

HMODULE WINAPI MyLoadLibraryW(
	LPCWSTR lpLibFileName
)
{
	HMODULE res;

	log("Checking  LoadLibraryW...");
	if (!strcmp(wchar_to_char(lpLibFileName), "C:\\Windows\\Syswow64\\userinit.exe"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Astaroth. T1093' ! Ñreating a dangerous file: ";
		msg += wchar_to_char(lpLibFileName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling LoadLibraryW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(wchar_to_char(lpLibFileName), "C:\\Windows\\System32\\userinit.exe"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Astaroth. T1093' ! Ñreating a dangerous file: ";
		msg += wchar_to_char(lpLibFileName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling LoadLibraryW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		string msg = "Call LoadLibraryW. LibName: ";
		msg += wchar_to_char(lpLibFileName);
		msg += ". ProcessName: ";
		msg += get_current_process();

		send_message(msg, 0);
		log(msg.c_str());
		return pLoadLibraryW(lpLibFileName);
	}
}

LSTATUS WINAPI MyRegCreateKeyA(
	HKEY   hKey,
	LPCSTR lpSubKey,
	PHKEY  phkResult
)
{
	LSTATUS res;

	log("Checking RegCreateKeyA...");
	if (!strcmp(lpSubKey, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows \"AppInit_DLLs\"=\"pserver32.dll\""))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'AppInit DLLs' ! Ñreating a dangerous key: ";
		msg += lpSubKey;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling RegCreateKeyA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpSubKey, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs – \%APPDATA\%\\Intel\\ResN32.dll"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'AppInit DLLs' ! Ñreating a dangerous key: ";
		msg += lpSubKey;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling RegCreateKeyA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpSubKey, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs – 0x1"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'AppInit DLLs' ! Ñreating a dangerous key: ";
		msg += lpSubKey;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling RegCreateKeyA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpSubKey, "SOFTWARE\\Microsoft\\Netsh"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Netsh' ! Ñreating a dangerous key: ";
		msg += lpSubKey;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling RegCreateKeyA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		log("Call RegCreateKeyA.");
		return pRegCreateKeyA(hKey, lpSubKey, phkResult);
	}
}

LSTATUS WINAPI MyRegCreateKeyW(
	HKEY   hKey,
	LPCWSTR lpSubKey,
	PHKEY  phkResult
)
{
	LSTATUS res;

	log("Checking RegCreateKeyW...");
	if (!strcmp(wchar_to_char(lpSubKey), "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows \"AppInit_DLLs\"=\"pserver32.dll\""))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'AppInit DLLs' ! Ñreating a dangerous key: ";
		msg += wchar_to_char(lpSubKey);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling RegCreateKeyW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(wchar_to_char(lpSubKey), "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs – \%APPDATA\%\\Intel\\ResN32.dll"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'AppInit DLLs' ! Ñreating a dangerous key: ";
		msg += wchar_to_char(lpSubKey);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling RegCreateKeyW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(wchar_to_char(lpSubKey), "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs – 0x1"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'AppInit DLLs' ! Ñreating a dangerous key: ";
		msg += wchar_to_char(lpSubKey);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling RegCreateKeyW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(wchar_to_char(lpSubKey), "SOFTWARE\\Microsoft\\Netsh"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Netsh' ! Ñreating a dangerous key: ";
		msg += wchar_to_char(lpSubKey);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling RegCreateKeyW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		log("Call RegCreateKeyW.");
		return pRegCreateKeyW(hKey, lpSubKey, phkResult);
	}
}

HANDLE WINAPI MyCreateFileA(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	HANDLE res;

	log("Checking CreateFileA...");
	if (!strcmp(lpFileName, "C:\\Windows\\Syswow64\\userinit.exe"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Astaroth. T1093' ! Ñreating a dangerous file:";
		msg += lpFileName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateFileA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpFileName, "C:\\Windows\\System32\\userinit.exe"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Astaroth. T1093' ! Ñreating a dangerous file: ";
		msg += lpFileName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateFileA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		log("Call CreateFileA.");
		return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}
}

/*
HANDLE WINAPI MyCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	HANDLE res;

	log("Checking CreateFileW...");
	if (!strcmp(wchar_to_char(lpFileName), "C:\\Windows\\Syswow64\\userinit.exe"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Astaroth. T1093' ! Ñreating a dangerous file:";
		msg += wchar_to_char(lpFileName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateFileW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(wchar_to_char(lpFileName), "C:\\Windows\\System32\\userinit.exe"))
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Astaroth. T1093' ! Ñreating a dangerous file: ";
		msg += wchar_to_char(lpFileName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateFileW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		log("Call CreateFileW.");
		return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}
}
*/

BOOL WINAPI MyCreateProcessA(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL res;
	
	log("Checking CreateProcessA...");
	if (!strcmp(lpApplicationName, "C:\\Windows\\wlxpgss.scr")) //Windows7
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += lpApplicationName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpApplicationName, "C:\\Windows\\system32\\PhotoScreensaver.scr")) //Windows7
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += lpApplicationName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpApplicationName, "C:\\Windows\\Syswow64\\PhotoScreensaver.scr")) //Windows7
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += lpApplicationName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpApplicationName, "C:\\Windows\\system32\\scrnsave.scr")) //Windows10
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += lpApplicationName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else if (!strcmp(lpApplicationName, "C:\\Windows\\Syswow64\\scrnsave.scr")) //Windows10
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += lpApplicationName;
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessA";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		string msg = "Call CreateProcessA. AppName: ";
		msg += lpApplicationName;
		msg += ". ProcessName: ";
		msg += get_current_process();

		send_message(msg, 0);
		log(msg.c_str());
		return pCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	}
}

BOOL WINAPI MyCreateProcessW(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL res;
	
	log("Checking CreateProcessW...");
	if (!strcmp(wchar_to_char(lpApplicationName), "C:\\Windows\\wlxpgss.scr")) //Windows7
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += wchar_to_char(lpApplicationName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return FALSE;
	}
	else if (!strcmp(wchar_to_char(lpApplicationName), "C:\\Windows\\system32\\PhotoScreensaver.scr")) //Windows7
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += wchar_to_char(lpApplicationName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return FALSE;
	}
	else if (!strcmp(wchar_to_char(lpApplicationName), "C:\\Windows\\Syswow64\\PhotoScreensaver.scr")) //Windows7
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += wchar_to_char(lpApplicationName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return FALSE;
	}
	else if (!strcmp(wchar_to_char(lpApplicationName), "C:\\Windows\\system32\\scrnsave.scr")) //Windows10
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += wchar_to_char(lpApplicationName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return FALSE;
	}
	else if (!strcmp(wchar_to_char(lpApplicationName), "C:\\Windows\\Syswow64\\scrnsave.scr")) //Windows10
	{
		string msg = "ALERT!!! Possible exploitation of attack technique: 'Screensaver' ! Launch a dangerous file: ";
		msg += wchar_to_char(lpApplicationName);
		msg += ". ProcessName: ";
		msg += get_current_process();
		msg += ". BLOCKED calling CreateProcessW";

		send_message(msg, 1);
		log(msg.c_str());
		send_message(get_current_process(), 4);
		return FALSE;
	}
	else
	{
		string msg = "Call CreateProcessW. AppName: ";
		msg += wchar_to_char(lpApplicationName);
		msg += ". ProcessName: ";
		msg += get_current_process();

		send_message(msg, 0);
		log(msg.c_str());
		return pCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH || dwReason == DLL_THREAD_ATTACH) {
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourAttach(&(PVOID&)pLoadLibraryA, MyLoadLibraryA);
		DetourAttach(&(PVOID&)pLoadLibraryW, MyLoadLibraryW);

		DetourAttach(&(PVOID&)pRegCreateKeyA, MyRegCreateKeyA);
		DetourAttach(&(PVOID&)pRegCreateKeyW, MyRegCreateKeyW);

		DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
		//DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);

		DetourAttach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
		DetourAttach(&(PVOID&)pCreateProcessW, MyCreateProcessW);

		DetourTransactionCommit();
	}

	if (dwReason == DLL_PROCESS_DETACH || dwReason == DLL_THREAD_DETACH)
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourAttach(&(PVOID&)pLoadLibraryA, MyLoadLibraryA);
		DetourAttach(&(PVOID&)pLoadLibraryW, MyLoadLibraryW);

		DetourAttach(&(PVOID&)pRegCreateKeyA, MyRegCreateKeyA);
		DetourAttach(&(PVOID&)pRegCreateKeyW, MyRegCreateKeyW);

		DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
		//DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);

		DetourAttach(&(PVOID&)pCreateProcessA, MyCreateProcessA);
		DetourAttach(&(PVOID&)pCreateProcessW, MyCreateProcessW);

		DetourTransactionCommit();
	}

	return TRUE;
}

string get_time()
{
	string reg_time;
	char local_time[32] = "";

	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(local_time, 32, "%d.%m.%Y %H:%M:%S", &tm);

	reg_time += "[";
	reg_time += local_time;
	reg_time += "] ";

	return reg_time;
}

void log(const char* msg) {
	char local_time[32] = "";
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(local_time, 32, "[%d.%m.%Y %H:%M:%S] ", &tm);
	FILE* pfile = fopen("C:\\UnterAV\\Logs\\log_dll_WINAPI.txt", "a+");
	fprintf(pfile, "%s%s\n", local_time, msg);
	fclose(pfile);
}

void send_message(string msg, int choice)
{
	DWORD last_error;
	unsigned int elapsed_seconds = 0;
	const unsigned int timeout_seconds = 5;

	HANDLE hNamedPipe;
	char szPipeName[256] = "\\\\.\\pipe\\WINAPIDLL";

	string message_to_send;

	// 0 - log; 1 - event
	if (choice == 0)
	{
		message_to_send += "log.";
	}
	else if (choice == 1)
	{
		message_to_send += "event.";
	}
	else if (choice == 4)
	{
		// bad
		message_to_send += "file(-).";
	}

	hNamedPipe = CreateFileA(szPipeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	
	while (INVALID_HANDLE_VALUE == hNamedPipe && elapsed_seconds < timeout_seconds)
	{
		last_error = GetLastError();

		if (last_error != ERROR_PIPE_BUSY)
		{
			break;
		}

		Sleep(1 * 1000);
		elapsed_seconds++;

		hNamedPipe = CreateFileA(szPipeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	}
	
	if (hNamedPipe == INVALID_HANDLE_VALUE)
	{
		string error = "CreateFile: Error ";
		error += to_string(GetLastError());
		log(error.c_str());
	}
	else
	{
		string msg_to_log;
		string temp = "Connected to ";
		temp += szPipeName;
		log(temp.c_str());

		message_to_send += msg;
		message_to_send += "(^_^)";

		DWORD  cbWritten;
		if (WriteFile(hNamedPipe, message_to_send.c_str(), message_to_send.length(), &cbWritten, NULL))
		{
			msg_to_log += "Sent message to";
			msg_to_log += szPipeName;
			msg_to_log += ": " + message_to_send;
			log(msg_to_log.c_str());
		}
		else
		{
			msg_to_log += "Error of sending message by pipe with name '";
			msg_to_log += szPipeName;
			msg_to_log += "'";
			log(msg_to_log.c_str());
		}
	}
	CloseHandle(hNamedPipe);
}

char* wchar_to_char(const wchar_t* pwchar)
{
	// get the number of characters in the string.
	int currentCharIndex = 0;
	char currentChar = pwchar[currentCharIndex];

	while (currentChar != '\0')
	{
		currentCharIndex++;
		currentChar = pwchar[currentCharIndex];
	}

	const int charCount = currentCharIndex + 1;

	// allocate a new block of memory size char (1 byte) instead of wide char (2 bytes)
	char* filePathC = (char*)malloc(sizeof(char) * charCount);

	for (int i = 0; i < charCount; i++)
	{
		// convert to char (1 byte)
		char character = pwchar[i];

		*filePathC = character;

		filePathC += sizeof(char);

	}
	filePathC += '\0';

	filePathC -= (sizeof(char) * charCount);

	return filePathC;
}

char* get_current_process()
{
	CHAR buffer[MAX_PATH] = "";
	GetModuleFileNameA(NULL, buffer, sizeof(buffer) / sizeof(buffer[0]));
	return buffer;
}