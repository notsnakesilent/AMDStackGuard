#pragma once
#include <windows.h>

#define IBS_DEVICE_NAME      L"\\Device\\IbsStackGuard"
#define IBS_DOSDEVICE_NAME   L"\\DosDevices\\IbsStackGuard"
#define IBS_WIN32_NAME       L"\\\\.\\IbsStackGuard"
#define FILE_DEVICE_IBS      0x8001

#define IOCTL_IBS_VALIDATE_USER_STACK \
    CTL_CODE(FILE_DEVICE_IBS, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _IBS_VALIDATION_INPUT {
    PVOID UserRsp; // pointer to the top of the user stack (where the return address is located)
	PVOID ExpectedReturn; // expected return address to validate against
} IBS_VALIDATION_INPUT, * PIBS_VALIDATION_INPUT;

typedef struct _IBS_VALIDATION_OUTPUT {
	PVOID    ValueAtRsp; // value read at UserRsp
	BOOLEAN  ProbeOk; // whether the probe to UserRsp succeeded
	BOOLEAN  Match; // whether ValueAtRsp matches ExpectedReturn
	NTSTATUS Status; // status of the operation
} IBS_VALIDATION_OUTPUT, * PIBS_VALIDATION_OUTPUT;
