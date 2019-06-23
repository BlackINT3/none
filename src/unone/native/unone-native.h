/****************************************************************************
**
** Copyright (C) 2019 BlackINT3
** Contact: https://github.com/BlackINT3/none
**
** GNU Lesser General Public License Usage (LGPL)
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 or version 3 as published by the Free
** Software Foundation and appearing in the file LICENSE.LGPLv21 and
** LICENSE.LGPLv3 included in the packaging of this file. Please review the
** following information to ensure the GNU Lesser General Public License
** requirements will be met: https://www.gnu.org/licenses/lgpl.html and
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
****************************************************************************/
#pragma once
#include <Windows.h>
#include <string>
#include "../internal/unone-internal.h"

#ifdef __cplusplus
extern "C" {
#endif
//
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

// NTSTATUS
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status)								((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS										((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL								((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH				((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL						((NTSTATUS)0xC0000023L)

#define POINTER32(Type) ULONG
#define POINTER64(Type) ULONG64

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} STRING, *PSTRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

//************************************************************************
typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _CLIENT_ID32
{
	DWORD UniqueProcess;
	DWORD UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

typedef struct _CLIENT_ID64
{
	DWORD64 UniqueProcess;
	DWORD64 UniqueThread;
} CLIENT_ID64, *PCLIENT_ID64;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG Buffer;
} STRING32, *PSTRING32;
typedef struct _STRING64
{
	USHORT Length;
	USHORT MaximumLength;
	ULONGLONG Buffer;
} STRING64, *PSTRING64;
typedef struct _UNICODE_STRING32
{
	USHORT  Length;
	USHORT  MaximumLength;
	ULONG Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;
typedef struct _UNICODE_STRING64
{
	USHORT  Length;
	USHORT  MaximumLength;
	ULONGLONG Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,                // 0        Y        N
	SystemProcessorInformation,            // 1        Y        N
	SystemPerformanceInformation,          // 2        Y        N
	SystemTimeOfDayInformation,            // 3        Y        N
	SystemNotImplemented1,                 // 4        Y        N
	SystemProcessesAndThreadsInformation,  // 5        Y        N
	SystemCallCounts,                      // 6        Y        N
	SystemConfigurationInformation,        // 7        Y        N
	SystemProcessorTimes,                  // 8        Y        N
	SystemGlobalFlag,                      // 9        Y        Y
	SystemNotImplemented2,                 // 10       Y        N
	SystemModuleInformation,               // 11       Y        N
	SystemLockInformation,               // 12       Y        N
	SystemNotImplemented3,               // 13       Y        N
	SystemNotImplemented4,               // 14       Y        N
	SystemNotImplemented5,               // 15       Y        N
	SystemHandleInformation,             // 16       Y        N
	SystemObjectInformation,             // 17       Y        N
	SystemPagefileInformation,           // 18       Y        N
	SystemInstructionEmulationCounts,    // 19       Y        N
	SystemInvalidInfoClass1,             // 20
	SystemCacheInformation,              // 21       Y        Y
	SystemPoolTagInformation,            // 22       Y        N
	SystemProcessorStatistics,           // 23       Y        N
	SystemDpcInformation,                // 24       Y        Y
	SystemNotImplemented6,               // 25       Y        N
	SystemLoadImage,                     // 26       N        Y
	SystemUnloadImage,                   // 27       N        Y
	SystemTimeAdjustment,                // 28       Y        Y
	SystemNotImplemented7,               // 29       Y        N
	SystemNotImplemented8,               // 30       Y        N
	SystemNotImplemented9,               // 31       Y        N
	SystemCrashDumpInformation,          // 32       Y        N
	SystemExceptionInformation,          // 33       Y        N
	SystemCrashDumpStateInformation,     // 34       Y        Y/N
	SystemKernelDebuggerInformation,     // 35       Y        N
	SystemContextSwitchInformation,      // 36       Y        N
	SystemRegistryQuotaInformation,      // 37       Y        Y
	SystemLoadAndCallImage,              // 38       N        Y
	SystemPrioritySeparation,            // 39       N        Y
	SystemNotImplemented10,              // 40       Y        N
	SystemNotImplemented11,              // 41       Y        N
	SystemInvalidInfoClass2,             // 42
	SystemInvalidInfoClass3,             // 43
	SystemTimeZoneInformation,           // 44       Y        N
	SystemLookasideInformation,          // 45       Y        N
	SystemSetTimeSlipEvent,              // 46       N        Y
	SystemCreateSession,                 // 47       N        Y
	SystemDeleteSession,                 // 48       N        Y
	SystemInvalidInfoClass4,             // 49
	SystemRangeStartInformation,         // 50       Y        N
	SystemVerifierInformation,           // 51       Y        Y
	SystemAddVerifier,                   // 52       N        Y
	SystemSessionProcessesInformation    // 53       Y        N
} SYSTEM_INFORMATION_CLASS;

typedef struct _VM_COUNTERS
{
	ULONG PeakVirtualSize;
	ULONG VirtualSize;
	ULONG PageFaultCount;
	ULONG PeakWorkingSetSize;
	ULONG WorkingSetSize;
	ULONG QuotaPeakPagedPoolUsage;
	ULONG QuotaPagedPoolUsage;
	ULONG QuotaPeakNonPagedPoolUsage;
	ULONG QuotaNonPagedPoolUsage;
	ULONG PagefileUsage;
	ULONG PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef enum
{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;

typedef enum _KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel
} KWAIT_REASON;
typedef LONG KPRIORITY;
typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	THREAD_STATE State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES   // Information Class 5
{
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;  // Windows 2000 only
	SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
	ThreadTimes, // q: KERNEL_USER_TIMES
	ThreadPriority, // s: KPRIORITY
	ThreadBasePriority, // s: LONG
	ThreadAffinityMask, // s: KAFFINITY
	ThreadImpersonationToken, // s: HANDLE
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress, // q: PVOID
	ThreadZeroTlsCell, // 10
	ThreadPerformanceCount, // q: LARGE_INTEGER
	ThreadAmILastThread, // q: ULONG
	ThreadIdealProcessor, // s: ULONG
	ThreadPriorityBoost, // qs: ULONG
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending, // q: ULONG
	ThreadHideFromDebugger, // s: void
	ThreadBreakOnTermination, // qs: ULONG
	ThreadSwitchLegacyState,
	ThreadIsTerminated, // 20, q: ULONG
	ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority, // qs: ULONG
	ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
	ThreadPagePriority, // q: ULONG
	ThreadActualBasePriority,
	ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context, // q: WOW64_CONTEXT
	ThreadGroupInformation, // 30, q: GROUP_AFFINITY
	ThreadUmsInformation,
	ThreadCounterProfiling,
	ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
	ThreadCpuAccountingInformation, // since WIN8
	ThreadSuspendCount, // since WINBLUE
	MaxThreadInfoClass
} THREADINFOCLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: HANDLE
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // 10
	ProcessLdtSize,
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // 30, q: HANDLE
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: ULONG
	ProcessExecuteFlags, // qs: ULONG
	ProcessResourceManagement,
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // q: ULONG
	ProcessInstrumentationCallback, // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR
	ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable, // since WINBLUE
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation, // 60, q: UNICODE_STRING
	ProcessProtectionInformation, // q: PS_PROTECTION
	MaxProcessInfoClass
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef	struct _CURDIR32
{
	UNICODE_STRING32	DosPath;
	ULONG	ConsoleHandle;
}CURDIR32, *PCURDIR32;
typedef	struct _CURDIR64
{
	UNICODE_STRING64	DosPath;
	PVOID64	ConsoleHandle;
}CURDIR64, *PCURDIR64;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_DRIVE_LETTER_CURDIR32
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, *PRTL_DRIVE_LETTER_CURDIR32;
typedef struct _RTL_DRIVE_LETTER_CURDIR64
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING64 DosPath;
} RTL_DRIVE_LETTER_CURDIR64, *PRTL_DRIVE_LETTER_CURDIR64;
#define RTL_MAX_DRIVE_LETTERS 32
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	POINTER32(HANDLE) ConsoleHandle;
	ULONG ConsoleFlags;
	POINTER32(HANDLE) StandardInput;
	POINTER32(HANDLE) StandardOutput;
	POINTER32(HANDLE) StandardError;
	CURDIR32 CurrentDirectory;
	UNICODE_STRING32 DllPath;
	UNICODE_STRING32 ImagePathName;
	UNICODE_STRING32 CommandLine;
	POINTER32(PVOID) Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING32 WindowTitle;
	UNICODE_STRING32 DesktopInfo;
	UNICODE_STRING32 ShellInfo;
	UNICODE_STRING32 RuntimeData;
	RTL_DRIVE_LETTER_CURDIR32 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	POINTER32(PVOID) PackageDependencyData;
	ULONG ProcessGroupId;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;
typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	POINTER64(HANDLE) ConsoleHandle;
	ULONG ConsoleFlags;
	POINTER64(HANDLE) StandardInput;
	POINTER64(HANDLE) StandardOutput;
	POINTER64(HANDLE) StandardError;
	CURDIR64 CurrentDirectory;
	UNICODE_STRING64 DllPath;
	UNICODE_STRING64 ImagePathName;
	UNICODE_STRING64 CommandLine;
	POINTER64(PVOID) Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING64 WindowTitle;
	UNICODE_STRING64 DesktopInfo;
	UNICODE_STRING64 ShellInfo;
	UNICODE_STRING64 RuntimeData;
	RTL_DRIVE_LETTER_CURDIR64 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	POINTER64(PVOID) PackageDependencyData;
	ULONG ProcessGroupId;
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;
typedef struct _PEB_LDR_DATA
{
	DWORD Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
}PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _PEB_LDR_DATA32
{
	DWORD Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
}PEB_LDR_DATA32, *PPEB_LDR_DATA32;
typedef struct _PEB_LDR_DATA64
{
	DWORD Length;
	UCHAR Initialized;
	PVOID64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	PVOID64 EntryInProgress;
}PEB_LDR_DATA64, *PPEB_LDR_DATA64;
typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR SpareBool;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
}PEB, *PPEB;
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR SpareBool;
	POINTER32(PVOID64) Mutant;
	POINTER32(PVOID64) ImageBaseAddress;
	POINTER32(PPEB_LDR_DATA) Ldr;
	POINTER32(PRTL_USER_PROCESS_PARAMETERS64) ProcessParameters;
}PEB32, *PPEB32;
typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR SpareBool;
	POINTER64(PVOID64) Mutant;
	POINTER64(PVOID64) ImageBaseAddress;
	POINTER64(PPEB_LDR_DATA) Ldr;
	POINTER64(PRTL_USER_PROCESS_PARAMETERS64) ProcessParameters;
}PEB64, *PPEB64;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	LIST_ENTRY HashLinks;
	DWORD TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	LIST_ENTRY32 HashLinks;
	DWORD TimeDateStamp;
	ULONG LoadedImports;
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
}LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	PVOID64 DllBase;
	PVOID64 EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	LIST_ENTRY64 HashLinks;
	DWORD TimeDateStamp;
	PVOID64 LoadedImports;
	PVOID64 EntryPointActivationContext;
	PVOID64 PatchInformation;
}LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef struct _PROCESS_BASIC_INFORMATION32 {
	NTSTATUS ExitStatus;
	ULONG PebBaseAddress;
	ULONG AffinityMask;
	KPRIORITY BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;
typedef struct _PROCESS_BASIC_INFORMATION64
{
	NTSTATUS ExitStatus;
	ULONG Pad1;
	ULONG64 PebBaseAddress;
	ULONG64 AffinityMask;
	KPRIORITY BasePriority;
	ULONG Pad2;
	ULONG64 UniqueProcessId;
	ULONG64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

typedef struct _TEB
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	// [TODO] more...
} TEB, *PTEB;
typedef struct _TEB32
{
	NT_TIB32 NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID32 ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	// [TODO] more...
} TEB32, *PTEB32;
typedef struct _TEB64
{
	NT_TIB64 NtTib;
	ULONG64 EnvironmentPointer;
	CLIENT_ID64 ClientId;
	ULONG64 ActiveRpcHandle;
	ULONG64 ThreadLocalStoragePointer;
	ULONG64 ProcessEnvironmentBlock;	//PPEB
	ULONG LastErrorValue;
	// [TODO] more...
} TEB64, *PTEB64;
typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
typedef struct _THREAD_BASIC_INFORMATION32
{
	NTSTATUS ExitStatus;
	ULONG TebBaseAddress;
	CLIENT_ID32 ClientId;
	ULONG AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION32, *PTHREAD_BASIC_INFORMATION32;
typedef struct _THREAD_BASIC_INFORMATION64
{
	ULONG ExitStatus;
	ULONG64 TebBaseAddress;
	CLIENT_ID64 ClientId;
	ULONG64 AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION64, *PTHREAD_BASIC_INFORMATION64;


// String [BEGIN]
/************************************************************************/
#define UNICODE_NULL ((WCHAR)0) // winnt
#ifndef INIT_UNICODE_STRING
#define INIT_UNICODE_STRING(us, wch)                 \
	us.MaximumLength = (USHORT)sizeof(wch);          \
	us.Length        = (USHORT)(wcslen(wch) * sizeof(WCHAR)); \
	us.Buffer        = wch
#endif

typedef VOID (NTAPI* __RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
);
// String [END]
/************************************************************************/

// Object [BEGIN]
/************************************************************************/
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY (0x0001)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) {   \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
	(p)->RootDirectory = r;                             \
	(p)->Attributes = a;                                \
	(p)->ObjectName = n;                                \
	(p)->SecurityDescriptor = s;                        \
	(p)->SecurityQualityOfService = NULL;               \
}
#endif

//
// Object Attributes structure
//
typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectHandleFlagInformation,
	ObjectSessionInformation,
	MaxObjectInfoClass  // MaxObjectInfoClass should always be the last enum
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {               // ntddk wdm nthal
	UNICODE_STRING Name;                                // ntddk wdm nthal
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;   // ntddk wdm nthal

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION {
	ULONG NumberOfTypes;
	// OBJECT_TYPE_INFORMATION TypeInformation;
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, *POBJECT_HANDLE_FLAG_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI *__NtQueryObject)(
	__in_opt HANDLE  Handle,
	__in OBJECT_INFORMATION_CLASS  ObjectInformationClass,
	__out_bcount_opt(ObjectInformationLength) PVOID  ObjectInformation,
	__in ULONG  ObjectInformationLength,
	__out_opt PULONG  ReturnLength
	);

typedef NTSTATUS (NTAPI* __NtOpenSymbolicLinkObject) (
	OUT PHANDLE SymbolicLinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI* __NtQuerySymbolicLinkObject) (
	IN HANDLE SymbolicLinkHandle,
	OUT PUNICODE_STRING NameString,
	OUT PULONG ResultLength OPTIONAL
);

typedef NTSTATUS (NTAPI* __NtClose)(
	IN  HANDLE Handle
);
#endif

// Object [END]
/************************************************************************/

// Rtl [BEGIN]
/************************************************************************/
typedef ULONG (WINAPI *__RtlNtStatusToDosError)(
	IN NTSTATUS Status
);
// Rtl [END]
/************************************************************************/

// NtReadVirtualMemory
typedef NTSTATUS (WINAPI *__NtReadVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN OUT PVOID Buffer,
	IN SIZE_T NumberOfBytesToRead,
	OUT SIZE_T* NumberOfBytesReaded
);

// NtWow64ReadVirtualMemory64
typedef NTSTATUS (WINAPI *__NtWow64ReadVirtualMemory64)(
	IN HANDLE ProcessHandle,
	IN PVOID64 BaseAddress,
	IN OUT PVOID Buffer,
	IN UINT64 NumberOfBytesToRead,
	OUT PUINT64 NumberOfBytesReaded
);

// security [BEGIN]
/************************************************************************/
#define SE_MACHINE_ACCOUNT_PRIVILEGE      (6L)
#define SE_TCB_PRIVILEGE                  (7L)
#define SE_SECURITY_PRIVILEGE             (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE       (9L)
#define SE_LOAD_DRIVER_PRIVILEGE          (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE       (11L)
#define SE_SYSTEMTIME_PRIVILEGE           (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE  (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE    (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE      (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE     (16L)
#define SE_BACKUP_PRIVILEGE               (17L)
#define SE_RESTORE_PRIVILEGE              (18L)
#define SE_SHUTDOWN_PRIVILEGE             (19L)
#define SE_DEBUG_PRIVILEGE                (20L)
#define SE_AUDIT_PRIVILEGE                (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE   (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE        (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE      (24L)
#define SE_UNDOCK_PRIVILEGE               (25L)
#define SE_SYNC_AGENT_PRIVILEGE           (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE    (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE        (28L)
#define SE_IMPERSONATE_PRIVILEGE          (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE        (30L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE       (SE_CREATE_GLOBAL_PRIVILEGE)

// RtlAdjustPrivilege
typedef NTSTATUS (NTAPI* __RtlAdjustPrivilege)(
	ULONG Privilege,
	BOOLEAN Enable,
	BOOLEAN Client,
	PBOOLEAN WasEnabled
);
// Security [END]
/************************************************************************/

/************************************************************************/
// Process/Thread/System [BEGIN]

// NtSuspendProcess
typedef NTSTATUS (NTAPI *__NtSuspendProcess)(
	__in HANDLE ProcessHandle
);

// NtQuerySystemInformation
typedef NTSTATUS (NTAPI *__NtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

// NtQueryInformationThread
typedef NTSTATUS (NTAPI *__NtQueryInformationThread)(
	IN   HANDLE   ThreadHandle,
	IN   THREADINFOCLASS   ThreadInformationClass,
	OUT  PVOID   ThreadInformation,
	IN   ULONG   ThreadInformationLength,
	OUT  PULONG   ReturnLength   OPTIONAL
);

// NtQueryInformationThread64
typedef NTSTATUS (NTAPI *__NtQueryInformationThread64)(
	IN   ULONG64   ThreadHandle,
	IN   THREADINFOCLASS   ThreadInformationClass,
	OUT  PVOID64   ThreadInformation,
	IN   ULONG   ThreadInformationLength,
	OUT  PVOID64   ReturnLength   OPTIONAL
);

// NtQueryInformationProcess
typedef NTSTATUS (NTAPI *__NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS InformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

// NtWow64QueryInformationProcess64
typedef NTSTATUS(NTAPI *__NtWow64QueryInformationProcess64)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS InformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

// NtResumeProcess
typedef NTSTATUS (NTAPI *__NtResumeProcess)(
	__in HANDLE ProcessHandle
);

// Wow64SuspendThread
typedef DWORD (WINAPI *__Wow64SuspendThread)(
	__in HANDLE hThread
);

// RtlCreateUserThread
typedef NTSTATUS(NTAPI *__RtlCreateUserThread)(
	IN HANDLE Process,
	IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG ZeroBits OPTIONAL,
	IN SIZE_T MaximumStackSize OPTIONAL,
	IN SIZE_T CommittedStackSize OPTIONAL,
	IN PVOID StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE Thread OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL
);

// Process [END]
/************************************************************************/

// RtlGetNtVersionNumbers
typedef VOID (NTAPI* __RtlGetNtVersionNumbers)(
	OUT PULONG MajorVer,
	OUT PULONG MinorVer,
	OUT PULONG BuildNumber
);

#ifdef __cplusplus
} // extern "C"
#endif

namespace UNONE {

UNONE_API NTSTATUS NtQuerySystemInfo(__in int type, __out std::string &info);

};