#include <ntddk.h>

#define FILE_DEVICE_IBS      0x8001
#define IOCTL_IBS_VALIDATE_USER_STACK \
    CTL_CODE(FILE_DEVICE_IBS, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct _IBS_VALIDATION_INPUT {
    PVOID UserRsp; // pointer to the top of the user stack(where the return address is located)
	PVOID ExpectedReturn; // expected return address to validate against
} IBS_VALIDATION_INPUT, * PIBS_VALIDATION_INPUT;

typedef struct _IBS_VALIDATION_OUTPUT {
	PVOID    ValueAtRsp; // value read at user RSP
	BOOLEAN  ProbeOk; // indicates if the probe succeeded
	BOOLEAN  Match;   // indicates if the value matched the expected return address
	NTSTATUS Status; // overall status of the operation
} IBS_VALIDATION_OUTPUT, * PIBS_VALIDATION_OUTPUT;

DRIVER_UNLOAD IbsUnload;
DRIVER_DISPATCH IbsCreateClose;
DRIVER_DISPATCH IbsDeviceControl;

VOID
IbsUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\IbsStackGuard");
    IoDeleteSymbolicLink(&symLink);

    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrint("[-] Driver unloaded\n");
}

NTSTATUS
IbsCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


PKTRAP_FRAME GetTrapFrameFromStack() {

    PVOID StackBase = IoGetInitialStack();

    ULONG_PTR Candidate = (ULONG_PTR)StackBase - sizeof(KTRAP_FRAME);

    PKTRAP_FRAME TrapFrame = (PKTRAP_FRAME)Candidate;

    if (TrapFrame->Rip < 0x7FFFFFFFFFFF && TrapFrame->Rsp < 0x7FFFFFFFFFFF && TrapFrame->Rsp > 0x1000) {
        return TrapFrame;
    }


    Candidate -= 0x100;
    TrapFrame = (PKTRAP_FRAME)Candidate;

    if (TrapFrame->Rip < 0x7FFFFFFFFFFF && TrapFrame->Rsp < 0x7FFFFFFFFFFF) {
        return TrapFrame;
    }

    return NULL;
}

NTSTATUS
IbsDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    if (irpSp->Parameters.DeviceIoControl.IoControlCode ==
        IOCTL_IBS_VALIDATE_USER_STACK)
    {
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(IBS_VALIDATION_INPUT) ||
            irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(IBS_VALIDATION_OUTPUT))
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            PIBS_VALIDATION_INPUT inBuf =
                (PIBS_VALIDATION_INPUT)Irp->AssociatedIrp.SystemBuffer;

            IBS_VALIDATION_INPUT inLocal = *inBuf;  // local copy

            PIBS_VALIDATION_OUTPUT out =
                (PIBS_VALIDATION_OUTPUT)Irp->AssociatedIrp.SystemBuffer;

            RtlZeroMemory(out, sizeof(*out));


            PVOID targetRsp = inLocal.UserRsp;

            PKTRAP_FRAME trapFrame = GetTrapFrameFromStack();

            if (trapFrame != NULL) {
                targetRsp = (PVOID)trapFrame->Rsp;
                DbgPrint("[-] SECURE: TrapFrame found via Stack Heuristic. Real RSP: %p, RIP: %p\n",
                    targetRsp, trapFrame->Rip);
            }
            else {
                DbgPrint("[-] WARNING: TrapFrame heuristic failed. Using User Input.\n");
            }
           
     
            out->ProbeOk = FALSE;
            out->Match = FALSE;
            out->Status = STATUS_UNSUCCESSFUL;

            __try {
              
                ProbeForRead(
                    targetRsp,
                    sizeof(PVOID),
                    sizeof(UCHAR) // Alignment
                );

          
                PVOID value = *(PVOID*)(targetRsp);

                out->ValueAtRsp = value;
                out->ProbeOk = TRUE;
                out->Status = STATUS_SUCCESS;

        
                if (value == inLocal.ExpectedReturn) {
                    out->Match = TRUE;
                    DbgPrint("[-] Match: [RSP] = %p, Expected = %p\n",
                        value, inLocal.ExpectedReturn);
                }
                else {
                    out->Match = FALSE;
                    DbgPrint("[-] MISMATCH: [RSP] = %p, Expected = %p\n",
                        value, inLocal.ExpectedReturn);
                }

                status = STATUS_SUCCESS;
                info = sizeof(*out);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                out->Status = status;
                out->ProbeOk = FALSE;
                out->Match = FALSE;
                info = sizeof(*out);

                DbgPrint("[-] Exception reading user stack at %p, status 0x%08X\n",
                    targetRsp, status);
            }
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}



NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\IbsStackGuard");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\IbsStackGuard");

    DbgPrint("[-] DriverEntry\n");


    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_IBS,
        0,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IbsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IbsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IbsDeviceControl;
    DriverObject->DriverUnload = IbsUnload;

    DbgPrint("[-] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}
