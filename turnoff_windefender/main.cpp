#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <map>

static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

static void SetWindowsSize(int width, int height) {
	HWND console = GetConsoleWindow();
	RECT r;
	GetWindowRect(console, &r); //stores the console's current dimensions
	MoveWindow(console, r.left, r.top, width, height, TRUE); // 900 width, 450 height
}

static bool IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;

	// Allocate and initialize a SID for the Administrators group.
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&ntAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&adminGroup)) {
		std::cerr << "AllocateAndInitializeSid Error: " << GetLastError() << std::endl;
		return false;
	}

	// Determine whether the SID of the Administrators group is enabled in the primary access token of the process.
	if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
		std::cerr << "CheckTokenMembership Error: " << GetLastError() << std::endl;
		isAdmin = FALSE;
	}

	// Free the SID after use.
	if (adminGroup) {
		FreeSid(adminGroup);
	}

	return isAdmin;
}

static int PressInputKey(std::string message) {
	std::cout << message;
	while (!_kbhit()) {}
	return _getch();
}

static int RebootSystem() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp{};

	// Get the current process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		std::cerr << "Error opening process token." << std::endl;
		return GetLastError();
	}

	// Getting the LUID for the system shutdown privilege
	if (!LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid)) {
		std::cerr << "Error obtaining LUID privilege." << std::endl;
		CloseHandle(hToken);
		return GetLastError();
	}

	tkp.PrivilegeCount = 1;  // Set the number of privileges to 1

	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  // Enable the privilege

	// Setting privileges for the process
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, nullptr)) {
		std::cerr << "An error occurred while setting privileges for the process." << std::endl;
		CloseHandle(hToken);
		return GetLastError();
	}

	// Closing the process token
	CloseHandle(hToken);

	// Suppress warning 'Rearchitect to avoid Reboot' because I want to reboot system
#pragma warning( push )
#pragma warning( disable : 28159 )
	if (!InitiateSystemShutdownExW(nullptr, nullptr, 0, TRUE, TRUE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_RECONFIG)) {
		std::cerr << "An error occurred when initiating system shutdown." << std::endl;
		return GetLastError();
	}
#pragma warning( pop )

	std::cout << "The system will reboot." << std::endl;

	return 0;
}

static void CreateRegistryKey(HKEY hKeyRoot, LPCSTR subKey) {
	SetConsoleTextAttribute(hConsole, 7);
	HKEY hKey;
	LONG lRes = RegCreateKeyExA(hKeyRoot, subKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
	if (lRes == ERROR_SUCCESS) {
		std::cout << "Registry key '" << subKey << "' created successfully." << std::endl;
		RegCloseKey(hKey);
	}
	else {
		std::cerr << "Failed to create registry key '" << subKey << "'. Error code: " << lRes << std::endl;
	}
}

static void SetRegistryMap(HKEY hKeyRoot, LPCSTR subKey, std::map<LPCSTR, DWORD> dict,
	WORD subKeyFore = FOREGROUND_INTENSITY, WORD keyValue = FOREGROUND_GREEN) {
	HKEY hKey;
	LONG lRes = RegOpenKeyExA(hKeyRoot, subKey, 0, KEY_SET_VALUE, &hKey);

	SetConsoleTextAttribute(hConsole, subKeyFore);
	if (lRes != ERROR_SUCCESS) {
		std::cerr << "Failed to open sub key: '" << subKey << "'. Error code: " << lRes << std::endl;
		return;
	}

	std::cout << "'" << subKey << "' sub key opened successfully" << std::endl;

	SetConsoleTextAttribute(hConsole, keyValue);
	for (std::pair<LPCSTR, DWORD> p : dict)
	{
		LPCSTR key = p.first;
		DWORD data = p.second;
		lRes = RegSetValueExA(hKey, key, 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
		if (lRes == ERROR_SUCCESS) {
			std::cout << "Registry (key: '" << key << "', value: '" << data << "') set successfully." << std::endl;
		}
		else {
			std::cout << "Failed to set registry (key: '" << key << "', value: '" << data << "'). Error code: " << lRes << std::endl;
		}
	}

	RegCloseKey(hKey);
}

int main() {
	SetWindowsSize(800, 475);

	CONSOLE_FONT_INFOEX cfi = { sizeof(cfi) };
	cfi.FontWeight = FW_BOLD;
	SetCurrentConsoleFontEx(hConsole, FALSE, &cfi);

	if (!IsRunningAsAdmin()) {
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		PressInputKey("Make sure to run this program as an administrator...");
		return 0;
	}

	#pragma region Maps

	std::map<LPCSTR, DWORD> winDefender = {
	{ "DisableAntiSpyware", 1 },
	{ "DisableRealtimeMonitoring", 1 },
	{ "DisableAntiVirus", 1 },
	{ "DisableSpecialRunningModes", 1 },
	{ "DisableRoutinelyTakingAction", 1 },
	{ "ServiceKeepAlive", 0 },
	};

	std::map<LPCSTR, DWORD> rTimeProt = {
	   { "DisableBehaviorMonitoring", 1 },
	   { "DisableOnAccessProtection", 1 },
	   { "DisableScanOnRealtimeEnable", 1 },
	   { "DisableRealtimeMonitoring", 1 },
	};

	std::map<LPCSTR, DWORD> signUpd = {
	   { "ForceUpdateFromMU", 0 },
	};

	std::map<LPCSTR, DWORD> spynet = {
	   { "DisableBlockAtFirstSeen", 1 },
	};

#pragma endregion

	HKEY hKey = HKEY_LOCAL_MACHINE;
	LPCSTR winDefSK = "SOFTWARE\\Policies\\Microsoft\\Windows Defender";
	SetRegistryMap(hKey, winDefSK, winDefender, 14);
	std::cout << std::endl;

	LPCSTR rTimeProtSK = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";
	CreateRegistryKey(hKey, rTimeProtSK);
	SetRegistryMap(hKey, rTimeProtSK, rTimeProt, 14);
	std::cout << std::endl;

	LPCSTR signUpdSK = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates";
	CreateRegistryKey(hKey, signUpdSK);
	SetRegistryMap(hKey, signUpdSK, signUpd, 14);
	std::cout << std::endl;

	LPCSTR spynetSK = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet";
	CreateRegistryKey(hKey, spynetSK);
	SetRegistryMap(hKey, spynetSK, spynet, 14);

	SetConsoleTextAttribute(hConsole, 11);
	std::cout << std::endl;
	std::cout << "Windows Defender has been disabled. Make sure to reboot your system..." << std::endl;

	int pressed = PressInputKey("Want to reboot your system now? (y / n):");
	std::cout << std::endl;
	switch (pressed)
	{
	case 'Y':
	case 'y':
		std::cout << "Rebooting..." << std::endl;
		Sleep(1000);
		RebootSystem();
		break;
	}

	return 0;
}