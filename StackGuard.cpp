#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include "LBRTester.h"

#pragma intrinsic(_AddressOfReturnAddress)

__declspec(noinline)
void TestIbsPoC(HANDLE hDevice, BOOL spoof)
{
    IBS_VALIDATION_INPUT  in;
    IBS_VALIDATION_OUTPUT out;
    DWORD bytesReturned = 0;

    PVOID* addrOfRet = (PVOID*)_AddressOfReturnAddress();
    PVOID  realRet = *addrOfRet;

    printf("[-] _AddressOfReturnAddress() (UserRsp) = %p\n", addrOfRet);
    printf("[-] *UserRsp (return address real)     = %p\n", realRet);

    PVOID expected = realRet;

    if (spoof) {

        // We simulate a stack spoofing: step on the return address of the stack with a FAKE address (that does not match ExpectedReturn).
        PVOID fakeRet = (PVOID)((ULONG_PTR)realRet ^ 0x1111111111111111ULL);

        *addrOfRet = fakeRet; 

        // ExpectedReturn is the same
        expected = realRet;
    }

    in.UserRsp = (PVOID)addrOfRet;
    in.ExpectedReturn = expected;

    ZeroMemory(&out, sizeof(out));

    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_IBS_VALIDATE_USER_STACK,
        &in,
        sizeof(in),
        &out,
        sizeof(out),
        &bytesReturned,
        NULL
    );

	// we restore the real return address 
    if (spoof) {
        *addrOfRet = realRet;
    }

    if (!ok) {
        DWORD err = GetLastError();
        printf("[-] DeviceIoControl failed: %lu (0x%08X)\n", err, err);
        return;
    }

    printf("\n[-] Driver response:\n");
    printf("      ProbeOk     = %s\n", out.ProbeOk ? "TRUE" : "FALSE");
    printf("      Status      = 0x%08X\n", out.Status);
    printf("      ValueAtRsp  = %p\n", out.ValueAtRsp);
    printf("      Match       = %s\n", out.Match ? "TRUE" : "FALSE");

    if (out.ProbeOk && out.Match) {
        printf("\n[-] OK: [RSP] is the same as ExpectedReturn (IBS).\n");
    }
    else if (out.ProbeOk && !out.Match) {
        printf("\n[-] ALERT: MISMATCH between [RSP] and ExpectedReturn (IBS)\n");
    }
    else {
        printf("\n[-] The user stack could not be read correctly.\n");
    }
}

int main(void)
{
    printf("[-] Opening device %ls ...\n", IBS_WIN32_NAME);

    HANDLE hDevice = CreateFileW(
        IBS_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("[-] CreateFile failed: %lu (0x%08X)\n", err, err);
        return 1;
    }

    printf("[-] Device opened successfully.\n\n");

    printf("=== Legit stack trace ===\n");
    TestIbsPoC(hDevice, FALSE);

    printf("\n\n=== Emulated stack spoofing ===\n");
    TestIbsPoC(hDevice, TRUE);

    CloseHandle(hDevice);
    return 0;
}
