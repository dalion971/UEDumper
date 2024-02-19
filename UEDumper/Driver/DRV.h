#include <windows.h>
#include <cstdint>


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(__fastcall* D3DKMTCheckOcclusion_t)(void* prama);

UINT ProcessId;
HWND GameWindow;
UINT GameThreadID;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	DWORD lpdwProcessId;
	DWORD tempTid = GetWindowThreadProcessId(hwnd, &lpdwProcessId);
	if (lpdwProcessId == ProcessId)
	{
		GameThreadID = tempTid;
		GameWindow = hwnd;
		return FALSE;
	}
	return TRUE;
}

typedef enum _HIDE_THREAD_TYPE {
	NONE,
	NMI,
	PSPCID_TABLE,
	KPRCB,
	THREAD_LIST
} HIDE_THREAD_TYPE;

class Driver
{
public:
	UINT ProcessId;
	UINT ThreadId;
	BOOL Attached = FALSE;
	D3DKMTCheckOcclusion_t fnD3DKMTCheckOcclusion;
	const bool Init() {
		HMODULE GDI32 = LoadLibraryA(("GDI32.dll"));
		if (GDI32) {
			uintptr_t pfnD3DKMTCheckOcclusion = (uintptr_t)GetProcAddress(GDI32, ("D3DKMTDestroyKeyedMutex"));
			if (pfnD3DKMTCheckOcclusion) {
				fnD3DKMTCheckOcclusion = (D3DKMTCheckOcclusion_t)pfnD3DKMTCheckOcclusion;
				if (fnD3DKMTCheckOcclusion) {
					this->ProcessId = GetCurrentProcessId();
					BOOL Check = this->CheckConnect();
					return Check;
				}
			}
		}
		return false;
	}

	const bool AttachByID(int Pid) {
		this->ProcessId = Pid;
		return true;
	}

	const bool Attach(const wchar_t* Classname) {
		GameWindow = FindWindowW(Classname, NULL);
		if (GameWindow) {
			ThreadId = GetWindowThreadProcessId(GameWindow, (LPDWORD)&ProcessId);
			Attached = TRUE;
			return true;
		}
		return false;
	}


	const NTSTATUS SendRequest(const UINT type, const PVOID args) {
		REQUEST_DATA req;
		NTSTATUS status;
		req.Type = type;
		req.Arguments = args;
		req.Status = &status;
		fnD3DKMTCheckOcclusion(&req);
		return status;
	}

	typedef struct Module { uint64_t addr; DWORD size; };
	const Module GetModuleBase(const wchar_t* ModuleName = 0) {
		if (!ModuleName)
			return { 0, 0 };
		REQUEST_MODULE req;
		uint64_t base = NULL;
		DWORD size = NULL;
		req.ProcessId = this->ProcessId;
		req.OutAddress = (PBYTE*)&base;
		req.OutSize = &size;
		wcscpy_s(req.Module, sizeof(req.Module) / sizeof(req.Module[0]), ModuleName);
		this->SendRequest(REQUEST_TYPE::MODULE, &req);
		return { base, size };
	}

	const BOOL CheckConnect() {
		REQUEST_CHECK req;
		uint64_t OutCheck = NULL;
		req.ProcessId = this->ProcessId;
		req.Out = (PBYTE*)&OutCheck;
		this->SendRequest(REQUEST_TYPE::CHECK, &req);
		return OutCheck == this->ProcessId * 2;
	}

	const BOOL ReadMemory(PVOID Addr, PVOID Buff, uint32_t Size, uint32_t Type = 0) {
		REQUEST_READ req;
		req.ProcessId = this->ProcessId;
		req.Src = Addr;
		req.Dest = Buff;
		req.Size = Size;
		req.Type = Type;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::READ, &req));
	}

	const BOOL WriteMemory(PVOID Addr, PVOID Buff, uint32_t Size, uint32_t Type = 0) {
		REQUEST_WRITE req;
		req.ProcessId = this->ProcessId;
		req.Src = Addr;
		req.Dest = Buff;
		req.Size = Size;
		req.Type = Type;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::WRITE, &req));
	}

	const BOOL ProtectMemory(PVOID Addr, uint32_t Size, PDWORD InOutProtect) {
		REQUEST_PROTECT req;
		req.ProcessId = this->ProcessId;
		req.Address = Addr;
		req.Size = Size;
		req.InOutProtect = InOutProtect;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::PROTECT, &req));
	}

	const BOOL AllocMemory(PVOID OutAddress, uint32_t Size, DWORD Protect) {
		REQUEST_ALLOC req;
		req.ProcessId = this->ProcessId;
		req.OutAddress = OutAddress;
		req.Size = Size;
		req.Protect = Protect;
		req.Type = 0;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::ALLOC, &req));
	}

	const BOOL AllocNoFreeMemory(PVOID OutAddress, uint32_t Size, DWORD Protect) {
		REQUEST_ALLOC req;
		req.ProcessId = this->ProcessId;
		req.OutAddress = OutAddress;
		req.Size = Size;
		req.Protect = Protect;
		req.Type = 1;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::ALLOC, &req));
	}

	const BOOL FreeMemory(PVOID Addr, uint32_t Size) {
		REQUEST_FREE req;
		req.ProcessId = this->ProcessId;
		req.Address = Addr;
		req.Size = Size;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::FREE, &req));
	}

	const BOOL QueryMemory(PVOID Addr, PMEMORY_BASIC_INFORMATION MemInfo) {
		REQUEST_QUERY req;
		req.ProcessId = this->ProcessId;
		req.Address = Addr;
		req.MemInfo = MemInfo;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::QUERY, &req));
	}

	const BOOL HideWindow(PVOID Handle, PVOID WindowEntryAddress) {
		REQUEST_HIDEWINDOW req;
		req.Handle = Handle;
		req.HandleKernelAddress = WindowEntryAddress;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::HIDEWINDOW, &req));
	}

	const BOOL ResumeWindow(PVOID NewHandle, PVOID WindowEntryAddress) {
		REQUEST_RESUMEWINDOW req;
		req.NewHandle = NewHandle;
		req.HandleKernelAddress = WindowEntryAddress;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::RESUMEWINDOW, &req));
	}

	const BOOL ByPassHWID(BOOL Enable) {
		REQUEST_HWID req;
		req.Enable = Enable;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::HWID, &req));
	}

	const BOOL GetKernelThread(PVOID Handle, PVOID KernelThreadAddress) {
		REQUEST_GETTHREAD req;
		req.Handle = Handle;
		req.KernelThreadAddress = KernelThreadAddress;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::GETTHREAD, &req));
	}

	const BOOL SetKernelThread(PVOID Handle, PVOID KernelThreadAddress) {
		REQUEST_SETTHREAD req;
		req.Handle = Handle;
		req.KernelThreadAddress = KernelThreadAddress;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::SETTHREAD, &req));
	}

	const BOOL ProtectCurrentThread() {
		REQUEST_THREADPROTECT req;
		req.ThreadHandle = GetCurrentThread();
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::THREADPROTECT, &req));
	}

	const BOOL ResumeCurrentThread() {
		REQUEST_THREADRESUME req;
		req.ThreadHandle = GetCurrentThread();
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::THREADRESUME, &req));
	}

	const BOOL SetThreadState(ULONG32 Tid, ULONG32 Tid2, HIDE_THREAD_TYPE HideType, BOOL State) {
		REQUEST_THREADSTATE req;
		req.PID = GetCurrentProcessId();
		req.ThreadID = Tid;
		req.HijackThreadID = Tid2;
		req.HideType = HideType;
		req.State = State;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::THREADSTATE, &req));
	}

	const BOOL SetCurPos(ULONG32 WinLogonPid, ULONG32 PosX, ULONG32 PosY) {
		REQUEST_MOUSEPOS req;
		req.WinLogonPid = WinLogonPid;
		req.PosX = PosX;
		req.PosY = PosY;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::MOUSEPOS, &req));
	}

	const BOOL MouseCallBack(ULONG32 PosX, ULONG32 PosY) {
		REQUEST_MOUSEPOSCALLBACK req;
		req.PosX = PosX;
		req.PosY = PosY;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::MOUSEPOSCALLBACK, &req));
	}

	const BOOL ProtectHandle(ULONG32 Handle, ULONG32 State) {
		REQUEST_HANDLEPROTECT req;
		req.PID = GetCurrentProcessId();
		req.ProtectHandle = Handle;
		req.State = State;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::HANDLEPROTECT, &req));
	}

	const BOOL AntiScreenShot(PVOID Handle, ULONG32 State) {
		REQUEST_ANTISCREENSHOT req;
		req.Handle = Handle;
		req.State = State;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::ANTISCREENSHOT, &req));
	}

	const BOOL RemoveVad(uint32_t ProcessId, PVOID Address) {
		REQUEST_REMOVEVAD req;
		req.ProcessId = (HANDLE)ProcessId;
		req.Address = Address;
		return NT_SUCCESS(this->SendRequest(REQUEST_TYPE::REMOVEVAD, &req));
	}
private:
	HANDLE hDriver;
	typedef enum _REQUEST_TYPE : UINT {
		CHECK,
		WRITE,
		READ,
		PROTECT,
		ALLOC,
		FREE,
		QUERY,
		MODULE,
		HIDEWINDOW,
		RESUMEWINDOW,
		HWID,
		GETTHREAD,
		SETTHREAD,
		THREADPROTECT,
		THREADRESUME,
		THREADSTATE,
		MOUSEPOS,
		MOUSEPOSCALLBACK,
		HANDLEPROTECT,
		ANTISCREENSHOT,
		REMOVEVAD
	} REQUEST_TYPE;

	typedef struct _REQUEST_DATA {
		UINT Type;
		PVOID Arguments;
		NTSTATUS* Status;
	} REQUEST_DATA, * PREQUEST_DATA;

	typedef struct _REQUEST_CHECK {
		DWORD ProcessId;
		PVOID Out;
	} REQUEST_CHECK, * PREQUEST_CHECK;

	typedef struct _REQUEST_WRITE {
		DWORD ProcessId;
		PVOID Src;
		PVOID Dest;
		DWORD Size;
		DWORD Type;
	} REQUEST_WRITE, * PREQUEST_WRITE;

	typedef struct _REQUEST_READ {
		DWORD ProcessId;
		PVOID Src;
		PVOID Dest;
		DWORD Size;
		DWORD Type;
	} REQUEST_READ, * PREQUEST_READ;

	typedef struct _REQUEST_PROTECT {
		DWORD ProcessId;
		PVOID Address;
		DWORD Size;
		PDWORD InOutProtect;
	} REQUEST_PROTECT, * PREQUEST_PROTECT;

	typedef struct _REQUEST_ALLOC {
		DWORD ProcessId;
		PVOID OutAddress;
		DWORD Size;
		DWORD Protect;
		DWORD Type;
	} REQUEST_ALLOC, * PREQUEST_ALLOC;

	typedef struct _REQUEST_FREE {
		DWORD ProcessId;
		PVOID Address;
		DWORD Size;
	} REQUEST_FREE, * PREQUEST_FREE;

	typedef struct _REQUEST_QUERY {
		DWORD ProcessId;
		PVOID Address;
		PMEMORY_BASIC_INFORMATION MemInfo;
	} REQUEST_QUERY, * PREQUEST_QUERY;

	typedef struct _REQUEST_MODULE {
		DWORD ProcessId;
		WCHAR Module[0xFF];
		PBYTE* OutAddress;
		DWORD* OutSize;
	} REQUEST_MODULE, * PREQUEST_MODULE;

	typedef struct _REQUEST_HIDEWINDOW {
		PVOID Handle;
		PVOID HandleKernelAddress;
	} REQUEST_HIDEWINDOW, * PREQUEST_HIDEWINDOW;

	typedef struct _REQUEST_RESUMEWINDOW {
		PVOID  NewHandle;
		PVOID  HandleKernelAddress;
	} REQUEST_RESUMEWINDOW, * PREQUEST_RESUMEWINDOW;

	typedef struct _REQUEST_HWID {
		BOOL Enable;
	} REQUEST_HWID, * PREQUEST_HWID;

	typedef struct _REQUEST_GETTHREAD {
		PVOID  Handle;
		PVOID  KernelThreadAddress;
	} REQUEST_GETTHREAD, * PREQUEST_GETTHREAD;

	typedef struct _REQUEST_SETTHREAD {
		PVOID  Handle;
		PVOID  KernelThreadAddress;
	} REQUEST_SETTHREAD, * PREQUEST_SETTHREAD;

	typedef struct _REQUEST_THREADPROTECT {
		PVOID  ThreadHandle;
	} REQUEST_THREADPROTECT, * PREQUEST_THREADPROTECT;

	typedef struct _REQUEST_THREADRESUME {
		PVOID  ThreadHandle;
	} REQUEST_THREADRESUME, * PREQUEST_THREADRESUME;

	typedef struct _REQUEST_THREADSTATE {
		ULONG32  PID;
		ULONG32  ThreadID;
		ULONG32  HijackThreadID;
		HIDE_THREAD_TYPE HideType;
		BOOL State;
	} REQUEST_THREADSTATE, * PREQUEST_THREADSTATE;

	typedef struct _REQUEST_MOUSEPOS {
		ULONG32 WinLogonPid;
		ULONG32  PosX;
		ULONG32  PosY;
	} REQUEST_MOUSEPOS, * PREQUEST_MOUSEPOS;

	typedef struct _REQUEST_MOUSEPOSCALLBACK {
		ULONG32  PosX;
		ULONG32  PosY;
	} REQUEST_MOUSEPOSCALLBACK, * PREQUEST_MOUSEPOSCALLBACK;

	typedef struct _REQUEST_HANDLEPROTECT {
		ULONG32  PID;
		ULONG32  ProtectHandle;
		ULONG32  State;
	} REQUEST_HANDLEPROTECT, * PREQUEST_HANDLEPROTECT;

	typedef struct _REQUEST_ANTISCREENSHOT {
		PVOID  Handle;
		ULONG32  State;
	} REQUEST_ANTISCREENSHOT, * PREQUEST_ANTISCREENSHOT;

	typedef struct _REQUEST_REMOVEVAD {
		HANDLE ProcessId;
		PVOID Address;
	} REQUEST_REMOVEVAD, * PREQUEST_REMOVEVAD;

	typedef struct _MEMORY_BASIC_INFORMATION {
		PVOID       BaseAddress;           //查询内存块所占的第一个页面基地址
		PVOID       AllocationBase;        //内存块所占的第一块区域基地址，小于等于BaseAddress，
		DWORD       AllocationProtect;     //区域被初次保留时赋予的保护属性
		SIZE_T      RegionSize;            //从BaseAddress开始，具有相同属性的页面的大小，
		DWORD       State;                 //页面的状态，有三种可能值MEM_COMMIT、MEM_FREE和MEM_RESERVE
		DWORD       Protect;               //页面的属性，其可能的取值与AllocationProtect相同
		DWORD       Type;                  //该内存块的类型，有三种可能值：MEM_IMAGE、MEM_MAPPED和MEM_PRIVATE
	} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;


};

static Driver* driver = new Driver;