#include "../testdlltag/testdll.h"
#include <WinSock2.h>


int main(int argc, char** argv)
{
  function_1(1, 2);
  function_2("AA");

  SOCKET s = 0;
  setsockopt(s, 0, 0, "1", 1);
  shutdown(s, 0);
  sendto(s, (const char*)"ABCDEF", 6, 0, NULL, 0);
  return 0;
}