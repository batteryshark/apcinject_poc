#include <windows.h>
#include <tlhelp32.h>

#include <vector>



#define EXPORTABLE __declspec(dllexport) 

#define WCS_SIZE(x) (wcslen(x) + 1) * 2

int InjectAPC(DWORD pid, LPCWSTR path_to_dll, DWORD is_64, DWORD64 p_lla) {
	if (is_64) {
		OutputDebugStringA("Injecting 64 Bit APC Process");
	}
	else {
		OutputDebugStringA("Injecting 32 Bit APC Process");
	}
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, pid);
	if (!hSnapshot) {return -1; }

	std::vector<DWORD> tid_lst{};

	THREADENTRY32 te32 = { sizeof(te32) };
	if (!Thread32First(hSnapshot, &te32)) { return -1; }
	if (te32.th32OwnerProcessID == pid) {tid_lst.push_back(te32.th32ThreadID);}

	while (Thread32Next(hSnapshot, &te32)) {
		if (te32.th32OwnerProcessID == pid) { tid_lst.push_back(te32.th32ThreadID); }
	}
	CloseHandle(hSnapshot);

	if (tid_lst.empty()) { return -1; }

	// If we have a list of TIDs to try, we can proceed.
	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	if (!hProcess) { return -1; }
	LPVOID pDll_Path;
	pDll_Path = VirtualAllocEx(hProcess, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!is_64 && (DWORD64)pDll_Path > ((1024 * 1024 * 1024) * 2)) {
		return -1;
	}
	if (!pDll_Path) {
		CloseHandle(hProcess);

		return -1;
	}


	if (!WriteProcessMemory(hProcess, pDll_Path, path_to_dll, WCS_SIZE(path_to_dll), nullptr)) {
		CloseHandle(hProcess);
		return -1;
	}



	HANDLE hThread;
	int apc_count = 0;
	for (int i = 0; i < tid_lst.size(); i++) {
		
		hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid_lst[i]);
		if (!hThread) { continue; }
		if (is_64) {
			if (!QueueUserAPC((PAPCFUNC)p_lla, hThread, (ULONG_PTR)pDll_Path)) {
				continue;
			}
		}
		else {
			DWORD p_ll32 = (DWORD)p_lla;
			if (!QueueUserAPC((PAPCFUNC)p_ll32, hThread, (ULONG_PTR)pDll_Path)) {
				continue;
			}
		}

		apc_count++;
	}

	return apc_count;

}
extern "C"{
// APC Injection of a given library path.
EXPORTABLE int InjectAPC32(DWORD pid, LPCWSTR path_to_dll, DWORD p_lla) {return InjectAPC(pid, path_to_dll, 0, (DWORD64)p_lla);}
EXPORTABLE int InjectAPC64(DWORD pid, LPCWSTR path_to_dll, DWORD64 p_lla) {return InjectAPC(pid, path_to_dll, 1, p_lla);}
}
