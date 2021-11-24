#include <iostream>
#include "api/KeyAuth.hpp"
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
#include <thread>

#include <fstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "urlmon.lib")

#pragma comment(lib, "Winmm.lib")

#include <iostream>
#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <tchar.h>
#include <string>
#include <cstring>
#include <atlstr.h>
#include <windef.h>
#include <sstream>
#include <strsafe.h>
#include <Windows.h>
#include <cstdlib>
#include <Lmcons.h>
#include <urlmon.h>
#include <tchar.h>
#include <sddl.h>
#include <stdio.h>
#include <string>
#include <strsafe.h>
#include <string>
#include <cstring>
#include <atlstr.h>
#include <windef.h>
#pragma once
#include <iostream>
#include <string>
#include <tchar.h>
#include <string.h>
#include <urlmon.h>
#pragma comment (lib, "urlmon.lib")
#include <iomanip> 
#include <iostream> 
#include <stdlib.h> 
#include <iomanip>
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#include "security.h"
#else
#endif
using namespace std;


using namespace std;

using namespace KeyAuth;
void error(std::string msg);
void debug();
std::string tm_to_readable_time(tm ctx);
std::string random_string(size_t length);
void exedetect();
void titledetect();
void driverdetect();
void killdbg();
void login();


std::string name = XorStr("");
std::string ownerid = XorStr("");
std::string secret = XorStr("");
std::string version = XorStr("");
//This is keyauth.com 
api KeyAuthApp(name, ownerid, secret, version);

size_t write_data(void* ptr, size_t size, size_t nmemb, FILE* stream) {
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
#define StrA VMProtectDecryptStringA
#define StrW VMProtectDecryptStringW


//------------------------------------------------------------------ ^ AUTHENTICATION + INCLUDE SHIT ^ ----------------------------------------------------------------------------------//


class Color
{
public:
	Color(int desiredColor) {
		consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		color = desiredColor;
	}

	friend ostream& operator<<(ostream& ss, Color obj) {
		SetConsoleTextAttribute(obj.consoleHandle, obj.color);
		return ss;
	}
private:
	int color;
	HANDLE consoleHandle;
	/*
	0 = black
	1 = blue
	2 = green
	3 = light blue
	4 = red
	5 = purple
	6 = gold
	7 = white
	*/
};


#pragma once
// #include "nigga.h"
#include <TlHelp32.h>

#pragma region colorsforconsole

#define black			0
#define bluelol			1
#define geenr			2
#define cyan			3
#define regd			4
#define magetana		5
#define crackerwhite	15
#pragma endregion colorsforconsole
CONSOLE_SCREEN_BUFFER_INFOEX info;
//------------------------------------------------------------------ ^ Color + Fancy Shit^ ----------------------------------------------------------------------------------//

void niggersmustdie()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11); std::string nonameniggermessage1("Please Press F2 To spoof");
}


#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);




void bsod()
{
	BOOLEAN bl;
	ULONG Response;
	RtlAdjustPrivilege(19, TRUE, FALSE, &bl); // Enable SeShutdownPrivilege
	NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); // Shutdown
}

int hours = 0;
int minutes = 0;
int seconds = 0;

void timer()
{

	system("CLS\n");
	cout << "\n please wait:\n";
	for  (int sec = 15; sec < 16; sec--)
		{
			
			cout << setw(2) << sec;
			cout.flush();

			Sleep(1000);
			cout << '\r';
			if (sec == 0)
			{
				system("CLS");
				
			}
			if (sec < 1)
				break;
	

	}
	
}
void AutismCloser() {
	cout << "\n [!]Please open your game of choice after loader closes.\n" << endl;
	cout << "[-] Closing in: 5" << endl;
	Sleep(1000);
	system("cls");
	cout << "\n [!]Please open your game of choice after loader closes.\n" << endl;
	cout << "[-] Closing in: 4" << endl;
	Sleep(1000);
	system("cls");
	cout << "\n [!]Please open your game of choice after loader closes.\n" << endl;
	cout << "[-] Closing in: 3" << endl;
	Sleep(1000);
	system("cls");
	cout << "\n [!]Please open your game of choice after loader closes.\n" << endl;
	cout << "[-] Closing in: 2" << endl;
	Sleep(1000);
	system("cls");
	cout << "\n [!]Please open your game of choice after loader closes.\n" << endl;
	cout << "[-] Closing in: 1" << endl;
	Sleep(1000);
	exit(1);
}
	

void Spoof()
{
	if (MessageBoxA(NULL, "Would you like to clean Fortnite traces", "Zeus.pro | cleaner", MB_YESNO) == IDYES)
	{
  //cleaner here
	}

	system("\n\nwmic diskdrive get serialnumber");
	system("\nwmic bios get serialnumber");
	system("\nwmic cpu get serialnumber");
	system("\nwmic baseboard get serialnumber");
	system("\nwmic memorychip get serialnumber");
	system("\nwmic desktopmonitor get Caption, MonitorType, MonitorManufacturer, Name");
	system("\n\n");

	if (MessageBoxA(NULL, "would you like to spoof Hwid ", "Zeus.pro | spoofing", MB_YESNO) == IDYES)
	{
		//Spoof here run driver mapper etc
	}


}
				

	void serials()
	{

		system("\n\nwmic diskdrive get serialnumber");
		system("\nwmic bios get serialnumber");
		system("\nwmic cpu get serialnumber");
		system("\nwmic baseboard get serialnumber");
		system("\nwmic memorychip get serialnumber");
		system("\nwmic desktopmonitor get Caption, MonitorType, MonitorManufacturer, Name");
		system("\ngetmac");
		Sleep(10000);
	
	}

void NiggerPrintMessage(const std::string& message, unsigned int Char_Seconds) {
	for (const char c : message)
	{
		std::cout << c << std::flush;

		Sleep(Char_Seconds);
	}
}


BOOL IsAppRunningAsAdminMode()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	// Allocate and initialize a SID of the administrators group.
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether the SID of administrators group is enabled in 
	// the primary access token of the process.
	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fIsRunAsAdmin;
}


void adminaccess()
{
	if (IsAppRunningAsAdminMode() == TRUE)
	{

	}
	else
	{
	    std::cout<< Color(4) << "[-] " << Color(7) << "Program NOT running as administrator!";
		Sleep(5000);
		exit(1);
	}
}



void printlogo()
{

	system("CLS");
	
	std::cout << Color(14) << R"(                                            
                                                                                                                          																			                                                                                   )";

}

HANDLE ConsoleHandle = 0;


/*   
    std::string version = "1.0";

    TCHAR versionurl[] = _T("www.yourtextfile.com/txt");
    TCHAR loaderlocation[] = _T("C:\\loaderversion.txt");
    HRESULT versionresult = URLDownloadToFile(nullptr, versionurl, loaderlocation, 0, nullptr);
*/



void Load_Nigger_Driver()
{
	
	system("CLS");//clears console
	std::cout << XorStr("\n\n Status: Active: (Expires: ");
	std::cout << tm_to_readable_time(KeyAuthApp.user_data.expiry);
	std::cout << XorStr(")");
	std::string message23 = ("\n[!] PLEASE MAKE SURE VANGUARD IS DISABLED ");
	std::string message1 = ("\n[>] zeus.pro | Spoofer ");
	std::string message233 = ("\n[-] Status | Undetected ");
	cout << "\n";
	NiggerPrintMessage(message23, 30);
	NiggerPrintMessage(message1, 30);
	NiggerPrintMessage(message233, 30); 
	{ cout << "\n";
	std::string message233 = ("\n[+] Please Press F1 To Spoof/clean");
	Sleep(5000);
	NiggerPrintMessage(message233, 30);
	SetConsoleTextAttribute(ConsoleHandle, crackerwhite);


	Sleep(800);
	SetConsoleTextAttribute(ConsoleHandle, bluelol);
	while (true)
	{
		Sleep(1000);
		if (GetAsyncKeyState(VK_F1))// If user presses F1 it will start proccess to spoof
		{
			std::string message3 = ("\n\n[+] Starting the process...\n");
			Beep(500, 500);
			Sleep(2000);
			NiggerPrintMessage(message3, 30);
			SetConsoleTextAttribute(ConsoleHandle, crackerwhite);
			Spoof();
			timer();
			AutismCloser();

	  	}
	   }	
	}
}


static const char alphanum[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

int stringLengthh = sizeof(alphanum) - 1;

char genRandomn()
{

	return alphanum[rand() % stringLengthh];
}
void Randomexe()
{
	srand(time(0));
	std::string Str;
	for (unsigned int i = 0; i < 7; ++i)
	{
		Str += genRandomn();

	}

	std::string rename = Str + ".exe";

	char filename[MAX_PATH];
	DWORD size = GetModuleFileNameA(NULL, filename, MAX_PATH);
	if (size)


		std::filesystem::rename(filename, rename);
}

static const char alphanumm[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz";

int stringLength1 = sizeof(alphanumm) - 1;

char genRandom1()
{

	return alphanumm[rand() % stringLength1];
}

void SetRandomTitle()
{
	srand(time(0));
	std::string Str;
	for (unsigned int i = 0; i < 20; ++i)
	{
		Str += genRandom1();

	}

	SetConsoleTitleA(Str.c_str());

}

int main()
{
	
	std::thread anti(debug); //  comment out if you're developing and getting debugger errors.
    //SetConsoleTitleA(random_string(20).c_str());
	char filename[] = "C:\\ProgramData\\woof.sys";


	if (remove(filename) != 0)
	adminaccess();
	SetRandomTitle();
	printlogo();
	Randomexe(); 
	std::cout << XorStr("\n Connecting to zeus.pro..");
	KeyAuthApp.init(); // required
	Sleep(2000);
	system("CLS");
	login(); // required

	if (KeyAuthApp.user_data.level == 1)
	{
		std::cout << XorStr("\n\n please contact support!!");
	}
	if (KeyAuthApp.user_data.level == 2)
	{
		std::cout << XorStr("\n\n please contact support!!");
	}

	Load_Nigger_Driver(); 
	
	
	}
	 

void login()
{
if (std::filesystem::exists("C:\\ProgramData\\" + name))
		{
		std::string key;
		std::ifstream InFile("C:\\ProgramData\\" + name, std::ios::in);
		std::getline(InFile, key);

		std::cout << XorStr("\n\n Activating Your Old key: ");
		std::cout << key;
		Sleep(1500);

		if (KeyAuthApp.login(key))
		{
		}
		else
		{
			std::string del = "C:\\ProgramData\\" + name;
			remove(del.c_str());
			goto A;
		}
	}
	else
	{
A:
	printlogo();
	std::cout << XorStr("\n\n Please enter your license key: ");
		bool authed = false;
		while (authed == false)
		{
			std::string serial;
			std::cin >> serial;
			if (KeyAuthApp.login(serial)) {
				std::ofstream OutFile("C:\\ProgramData\\" + name, std::ios::out);
				OutFile << serial;
				OutFile.close();
				authed = true;
			}
			else {
				Sleep(2500);
				system("CLS");
				goto A;
			}
		}
	}
}

NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue)
{
	return NTSTATUS();
}

NTSTATUS NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response)
{
	return NTSTATUS();
}

bool IsProcessRunningQQ(const wchar_t* processName)
{
	bool exists = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
		while (Process32Next(snapshot, &entry)) {


			if (!_wcsicmp(entry.szExeFile, processName))
				exists = true;
		}

	CloseHandle(snapshot);
	return exists;
}


void exedetect()
{


	if (IsProcessRunningQQ(XorStr(L"KsDumperClient.exe").c_str()))
	{
		KeyAuthApp.log("KsDumperClient Detected");
		error(XorStr("KsDumper"));
	}
	else if (IsProcessRunningQQ(XorStr(L"Taskmgr.exe").c_str()))
	{
		KeyAuthApp.log("Taskmgr Detected");
		error(XorStr("Taskmgr"));
	}
	else if (IsProcessRunningQQ(XorStr(L"HTTPDebuggerUI.exe").c_str()))
	{
		KeyAuthApp.log("HTTP DebuggerUi Detected");
		error(XorStr("HTTP Debugger"));
	}
	else if (IsProcessRunningQQ(XorStr(L"HTTPDebuggerSvc.exe").c_str()))
	{
		KeyAuthApp.log("HTTP Debuggersvc Detected");
		error(XorStr("HTTP Debugger Service"));
	}
	else if (IsProcessRunningQQ(XorStr(L"FolderChangesView.exe").c_str()))
	{
		KeyAuthApp.log("FolderChangesView Detected");
		error(XorStr("FolderChangesView"));
	}
	else if (IsProcessRunningQQ(XorStr(L"ProcessHacker.exe").c_str()))
	{
		KeyAuthApp.log("ProcessHacker Detected");
		error(XorStr("Process Hacker"));
	}
	else if (IsProcessRunningQQ(XorStr(L"procmon.exe").c_str()))
	{
		KeyAuthApp.log("procmon.exe Detected");
		error(XorStr("Process Monitor"));
	}
	else if (IsProcessRunningQQ(XorStr(L"idaq.exe").c_str()))
	{
		KeyAuthApp.log("idaq.exe Detected");
		error(XorStr("IDA"));
	}
	else if (IsProcessRunningQQ(XorStr(L"idaq64.exe").c_str()))
	{
		KeyAuthApp.log("idaq64.exe Detected");
		error(XorStr("IDA"));
	}
	else if (IsProcessRunningQQ(XorStr(L"Wireshark.exe").c_str()))
	{
		KeyAuthApp.log("Wireshark Detected");
		error(XorStr("WireShark"));
	}
	else if (IsProcessRunningQQ(XorStr(L"Fiddler.exe").c_str()))
	{
		KeyAuthApp.log("Fiddler Detected");
		error(XorStr("Fiddler"));
	}
	else if (IsProcessRunningQQ(XorStr(L"Xenos64.exe").c_str()))
	{
		KeyAuthApp.log("Xenos64 Detected");
		error(XorStr("Xenos64"));
	}
	else if (IsProcessRunningQQ(XorStr(L"Cheat Engine.exe").c_str()))
	{
		KeyAuthApp.log("Cheat Engine Detected");
		error(XorStr("Cheat Engine"));
	}
	else if (IsProcessRunningQQ(XorStr(L"HTTP Debugger Windows Service (32 bit).exe").c_str()))
	{
		KeyAuthApp.log("HTTP Debugger Detected");
		error(XorStr("HTTP Debugger"));
	}
	else if (IsProcessRunningQQ(XorStr(L"KsDumper.exe").c_str()))
	{
		KeyAuthApp.log("KsDumper Detected");
		error(XorStr("KsDumper"));
	}
	else if (IsProcessRunningQQ(XorStr(L"CFFExplorer.exe").c_str()))
	{
		KeyAuthApp.log("CFFExplorer Detected");
		error(XorStr("CFFExplorer"));
	}
	else if (IsProcessRunningQQ(XorStr(L"x64dbg.exe").c_str()))
	{
		KeyAuthApp.log("x64dbg Detected");
		error(XorStr("x64DBG"));
	}
}

void titledetect()
{
	HWND window;
	window = FindWindow(0, XorStr((L"IDA: Quick start")).c_str());
	if (window)
	{
		error(XorStr("IDA"));
	}

	window = FindWindow(0, XorStr((L"Memory Viewer")).c_str());
	if (window)
	{
		error(XorStr("Cheat Engine"));
	}

	window = FindWindow(0, XorStr((L"Process List")).c_str());
	if (window)
	{
		error(XorStr("Cheat Engine"));
	}

	window = FindWindow(0, XorStr((L"KsDumper")).c_str());
	if (window)
	{
		error(XorStr("KsDumper"));
	}
}

void driverdetect()
{
	const TCHAR* devices[] = {
_T("\\\\.\\NiGgEr"),
_T("\\\\.\\KsDumper")
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = _T("");
		if (hFile != INVALID_HANDLE_VALUE) {
			KeyAuthApp.log("KsDumper driver Detected!!" + KeyAuthApp.user_data.key);
			system(XorStr("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul").c_str());
			exit(1);
			exit(0);
		}
		else
		{

		}
	}
}


PVOID AntiRevers(HMODULE dwModule)
{
	PVOID pEntry = NULL;
	PIMAGE_DOS_HEADER pId = (PIMAGE_DOS_HEADER)dwModule;
	PIMAGE_NT_HEADERS pInt = (PIMAGE_NT_HEADERS)(dwModule + pId->e_lfanew);
	pEntry = dwModule + pInt->OptionalHeader.BaseOfCode;
	return pEntry;
}




inline bool Int2DCheck()
{
	__try
	{
		__asm
		{
			int 0x2d
			xor eax, eax
			add eax, 2
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}






void error(std::string msg)
{
	system(("START CMD /C \"COLOR C && TITLE Protection && ECHO INFO: ERROR: " + msg + " Detected. Please close and try again. && TIMEOUT 10 >nul").c_str());
	exit(1);
	exit(0);
}


void debug()
{
	while (true)
	{
		killdbg();
		exedetect();
		titledetect();
		driverdetect();

	}
}

void killdbg()
{
	system(XorStr("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1").c_str());
	system(XorStr("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1").c_str());
	system(XorStr("sc stop HTTPDebuggerPro >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1").c_str());
}

static std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}

std::string tm_to_readable_time(tm ctx) {
	char buffer[25];

	strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

	return std::string(buffer);
}
