#include <Windows.h>
#include <winsock.h>

typedef int (WINAPI *PSENDTO)(
  SOCKET s,
  const char* buf,
  int len,
  int flags,
  const struct sockaddr* to,
  int tolen
  );

static PSENDTO g_original_sendto = nullptr;
static HANDLE g_thread = 0;

int mysendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
  MessageBoxA(0, "HOOK", "HOOK", 0);
  return g_original_sendto(s, buf, len, flags, to, tolen);
}

DWORD WINAPI install_iat_hook(LPVOID)
{
  HMODULE ws2_32_dll = LoadLibraryA("WS2_32.DLL");
  g_original_sendto = (PSENDTO)GetProcAddress(ws2_32_dll, "sendto");

  DWORD sleep_interval = 50;
  while (true)
  {
    sleep_interval = min(2000, sleep_interval*2);
    Sleep(sleep_interval);

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)GetModuleHandle(NULL);
    if (dos_header == nullptr)
    {
      continue;
    }

    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);
    if (nt_headers == nullptr)
    {
      continue;
    }

    DWORD import_directory_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)((char*)dos_header + import_directory_rva);

    bool sendto_not_patched = true;
    while (sendto_not_patched)
    {
      if (_stricmp("WS2_32.DLL", (char*)dos_header + import_descriptor->Name) == 0)
      {
        IMAGE_THUNK_DATA* first_thunk = (IMAGE_THUNK_DATA*)((char*)dos_header + import_descriptor->FirstThunk);

        while (first_thunk->u1.AddressOfData != 0)
        {
          if ((PSENDTO)first_thunk->u1.AddressOfData == g_original_sendto)
          {
            DebugBreak();
            auto page_start = (ptrdiff_t)first_thunk - ((ptrdiff_t)first_thunk % 4096);
            DWORD old_protect;
            VirtualProtect((LPVOID)page_start, 4096, PAGE_READWRITE, &old_protect);
            first_thunk->u1.AddressOfData = (decltype(first_thunk->u1.AddressOfData))(&mysendto);
            VirtualProtect((LPVOID)page_start, 4096, old_protect, &old_protect);
            sendto_not_patched = false;
            break;
          }
          ++first_thunk;
        }
      }
      if (import_descriptor->OriginalFirstThunk == 0)
      {
        break;
      }
      ++import_descriptor;
    }
    if (!sendto_not_patched)
    {
      break;
    }
  }

  g_thread = 0;
  ExitThread(0);
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
  switch (reason)
  {
  case DLL_PROCESS_ATTACH:
    g_thread = CreateThread(nullptr, 0, &install_iat_hook, nullptr, 0, nullptr);
    break;
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
    break;
  case DLL_PROCESS_DETACH:
    if (g_thread != 0)
    {
      TerminateThread(g_thread, 1);
    }
    break;
  }
  return TRUE;
}