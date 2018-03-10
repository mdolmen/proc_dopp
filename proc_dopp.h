#pragma once

#include <Windows.h>
#include <SubAuth.h>

/*
 * cf. https://github.com/hasherezade/process_doppelganging/blob/master/ntdll_types
 */
#define PS_INHERIT_HANDLES 4

/*
 * Source : https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wudfwdm/ns-wudfwdm-_object_attributes
 * 
 * We need to declare this structure because it is not in the standard header,
 * we could probably do another way by copying the kernel headers into the project.
 */
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/*
 * Pointer to the NtCreateSection() function.
 */
typedef NTSTATUS (NTAPI *NT_CREATE_SECTION)(
	PHANDLE				SectionHandle, 
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes,
	PLARGE_INTEGER		MaximumSize,
	ULONG				SectionPageProtection,
	ULONG				AllocationAttributes,
	HANDLE				FileHandle
);

/*
 * Pointer to the NtCreatProcessEx() function.
 */
typedef NTSTATUS (NTAPI *NT_CREATE_PROCESS_EX)
(
    OUT PHANDLE				ProcessHandle,
    IN ACCESS_MASK			DesiredAccess,
    IN POBJECT_ATTRIBUTES	ObjectAttributes	OPTIONAL,
    IN HANDLE				ParentProcess,
    IN ULONG				Flags,
    IN HANDLE				SectionHandle		OPTIONAL,
    IN HANDLE				DebugPort			OPTIONAL,
    IN HANDLE				ExceptionPort		OPTIONAL,
    IN BOOLEAN				InJob
);

/*
 * Pointer to the NtCreatThreadEx() function.
 */
typedef NTSTATUS (NTAPI *NT_CREATE_THREAD_EX) (
    OUT PHANDLE				ThreadHandle, 
    IN  ACCESS_MASK			DesiredAccess, 
    IN  POBJECT_ATTRIBUTES	ObjectAttributes	OPTIONAL, 
    IN  HANDLE				ProcessHandle,
    IN  PVOID				StartRoutine,
    IN  PVOID				Argument			OPTIONAL,
    IN  ULONG				CreateFlags,
    IN  ULONG_PTR			ZeroBits, 
    IN  SIZE_T				StackSize			OPTIONAL,
    IN  SIZE_T				MaximumStackSize	OPTIONAL, 
    IN  PVOID				AttributeList		OPTIONAL
);