#pragma once

#ifdef TEST_EXPORTS
#define TESTAPI __declspec(dllexport)
#else
#define TESTAPI __declspec(dllimport)
#endif

void TESTAPI function_1(int a, int b);
int TESTAPI function_2(char* v);