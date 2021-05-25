#pragma once

BOOL getToken(HANDLE elevProc);

BOOL UserFromProc(HANDLE hProc, char* szUserOut, char* szDomOut);

void UserFromPID(DWORD dwProcID, char* szUserOut, char* szDomOut);

BOOL ListGroupsFromProc(HANDLE hProc);

void LoopTokens(void);

BOOL executeSliv(HANDLE hProc);

BOOL CheckWindowsPrivilege(WCHAR* Privilege, HANDLE token);

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
);


void (WINAPI* pRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

BOOLEAN(NTAPI* pRtlEqualUnicodeString)(
	PUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
	);

typedef struct _PRIVARR {
	DWORD               PrivilegeCount;
	LUID_AND_ATTRIBUTES Privileges[4];
} PRIVARR, * PPRIVARR;


BOOL createSacrificial(HANDLE hProc);

BOOL enablePrivs(HANDLE hToken, int privCount, wchar_t* privs[]);

int Inject(HANDLE hProc, unsigned char* payload, unsigned int payload_len);
BOOL injectHandler(HANDLE hProc);
BOOL elevateNInject( HANDLE parentProc, HANDLE debugPp);
BOOL enableTokenPrivs(HANDLE hToken);

int InjectVIEW(HANDLE hProc, unsigned char* payload, unsigned int payload_len);
BOOL classicInject(HANDLE hProc,int resource);
BOOL spoofParent(HANDLE parent);