#define TEST_EXPORTS
#include "testdll.h"

#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	OutputDebugStringA("!!!!dll loaded!!!\n");
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

void function_1(int a, int b)
{
  MessageBoxA(0, "FUNCTION1", "F1", 0);
}

int function_2(char* v)
{
  MessageBoxA(0, "FUNCTION2", "F2", 0);
  return 1;
}

