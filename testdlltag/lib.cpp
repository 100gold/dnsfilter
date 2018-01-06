#define TEST_EXPORTS
#include "testdll.h"
#include <Windows.h>

void function_1(int a, int b)
{
  MessageBoxA(0, "FUNCTION1", "F1", 0);
}

int function_2(char* v)
{
  MessageBoxA(0, "FUNCTION2", "F2", 0);
  return 1;
}

