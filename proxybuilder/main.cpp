#include <stdio.h>
#include <vector>
#include <string>
#include <exception>
#include <fstream>

#include <Windows.h>
#include <Imagehlp.h>


#define WITH_ALIGNMENT(_VAL_, _ALIGNMENT_) \
  ((_VAL_) % (_ALIGNMENT_) == 0 ? (_VAL_) : ((_VAL_) - ((_VAL_) % (_ALIGNMENT_)) + (_ALIGNMENT_)))


class NewSection
{
public:
  NewSection(DWORD rva)
  {
    m_data.reserve(128 * 1024);
    m_start_rva = rva;
  }

  DWORD append(const void* data, size_t size)
  {
    DWORD rva = expand(size);
    memcpy(rva2ptr(rva), data, size);
    return rva;
  }

  void* rva2ptr(DWORD rva)
  {
    return &m_data[rva - m_start_rva];
  }

  DWORD expand(size_t size)
  {
    DWORD result = m_data.size() + m_start_rva;
    m_data.resize(m_data.size() + size);
    return result;
  }

  DWORD m_start_rva;
  std::vector<std::uint8_t> m_data;
};


struct SectionDataView
{
  void* data_ptr;
  DWORD size;
  SectionDataView(void* a, DWORD b) : data_ptr(a), size(b) {};
};


class PEImage
{
public:
  PEImage(char* filename)
  {
    m_file_h = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    m_map_h = CreateFileMapping(m_file_h, NULL, PAGE_READONLY, 0, 0, NULL);
    m_file_data = (char*)MapViewOfFile(m_map_h, FILE_MAP_READ, 0, 0, 0);
    if (m_file_data == nullptr)
    {
      throw std::runtime_error("file not found\n");
    }

    m_dos_header = (IMAGE_DOS_HEADER*)m_file_data;
    m_nt_header = (IMAGE_NT_HEADERS64*)(m_file_data + m_dos_header->e_lfanew);
    if (m_nt_header->FileHeader.Machine != 0x8664)
    {
      throw std::runtime_error("bad pe file (32bit application?)\n");
    }

    m_sections = (IMAGE_SECTION_HEADER*)((char*)&m_nt_header->OptionalHeader + m_nt_header->FileHeader.SizeOfOptionalHeader);
  }

  IMAGE_EXPORT_DIRECTORY* read_exports()
  {
    if (m_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
    {
      throw std::runtime_error("no export section\n");
    }

    auto export_rva = m_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    try
    {
      return (IMAGE_EXPORT_DIRECTORY*)rva2ptr(export_rva);
    }
    catch (const std::runtime_error&) 
    {
      throw std::runtime_error("parsing error, export section not found\n");
    }
  }

  DWORD make_new_section_rva()
  {
    DWORD new_section_rva = 0;
    for (size_t i = 0; i < m_nt_header->FileHeader.NumberOfSections; ++i)
    {
      new_section_rva = max(new_section_rva, m_sections[i].VirtualAddress + m_sections[i].Misc.VirtualSize);
    }
    return WITH_ALIGNMENT(new_section_rva, m_nt_header->OptionalHeader.SectionAlignment);
  }

  void* rva2ptr(DWORD rva)
  {
    for (size_t i = 0; i < m_nt_header->FileHeader.NumberOfSections; ++i)
    {
      if ((m_sections[i].VirtualAddress <= rva) && (m_sections[i].Misc.VirtualSize + m_sections[i].VirtualAddress >= rva))
      {
        return m_file_data + m_sections[i].PointerToRawData + rva - m_sections[i].VirtualAddress;
      }
    }
    
    throw std::runtime_error("invalid rva");
  }

  void merge_export_section(std::vector<std::uint8_t>& result, NewSection& new_section)
  {
    // Size calc
    size_t old_total_header_size = (ptrdiff_t)&m_sections[m_nt_header->FileHeader.NumberOfSections] - (ptrdiff_t)m_file_data;
    size_t new_total_header_size = old_total_header_size + sizeof(IMAGE_SECTION_HEADER);
    size_t new_total_header_size_with_padding = WITH_ALIGNMENT(new_total_header_size, m_nt_header->OptionalHeader.FileAlignment);

    std::vector<SectionDataView> section_data;
    section_data.reserve(m_nt_header->FileHeader.NumberOfSections + 1);
    for (size_t i = 0; i < m_nt_header->FileHeader.NumberOfSections; ++i)
    {
      section_data.emplace_back(m_file_data + m_sections[i].PointerToRawData, m_sections[i].Misc.VirtualSize);
    }
    section_data.emplace_back(new_section.m_data.data(), new_section.m_data.size());

    size_t new_total_size = new_total_header_size_with_padding;
    for (auto& data_view : section_data)
    {
      if (data_view.data_ptr != m_file_data)
      {
        new_total_size += WITH_ALIGNMENT(data_view.size, m_nt_header->OptionalHeader.FileAlignment);
      }
    }

    result.resize(new_total_size);
    memset(result.data(), 0, result.size());

    // Copy data & fix offsets
    memcpy(&result[0], m_file_data, old_total_header_size);

    auto new_nt_header = (IMAGE_NT_HEADERS64*)((ptrdiff_t)&result[0] + ((ptrdiff_t)m_nt_header - (ptrdiff_t)m_file_data));
    new_nt_header->FileHeader.NumberOfSections += 1;
    new_nt_header->OptionalHeader.SizeOfImage += WITH_ALIGNMENT(new_section.m_data.size(), m_nt_header->OptionalHeader.SectionAlignment);
    new_nt_header->OptionalHeader.SizeOfHeaders = new_total_header_size_with_padding;
    new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = new_section.m_data.size();
    new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = new_section.m_start_rva;
    // Does SizeOfInitializedData needs to be fixed?

    auto new_all_sections = (IMAGE_SECTION_HEADER*)((char*)&new_nt_header->OptionalHeader + new_nt_header->FileHeader.SizeOfOptionalHeader);
    IMAGE_SECTION_HEADER* new_section_header = &new_all_sections[new_nt_header->FileHeader.NumberOfSections-1];

    strcpy((char*)new_section_header->Name, "higuys!");
    new_section_header->Misc.VirtualSize = new_section.m_data.size();
    new_section_header->VirtualAddress = new_section.m_start_rva;
    new_section_header->SizeOfRawData = WITH_ALIGNMENT(new_section.m_data.size(), m_nt_header->OptionalHeader.FileAlignment);
    //new_section_header->PointerToRawData will be fixed with other sections
    new_section_header->PointerToRelocations = 0;
    new_section_header->PointerToLinenumbers = 0;
    new_section_header->NumberOfRelocations = 0;
    new_section_header->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    std::uint8_t* last_byte = result.data() + new_total_header_size_with_padding;
    for (size_t i = 0; i < section_data.size(); ++i)
    {
      if (section_data[i].data_ptr != m_file_data)
      {
        memcpy(last_byte, section_data[i].data_ptr, section_data[i].size);
        new_all_sections[i].PointerToRawData = (DWORD)(last_byte - result.data());
        last_byte += WITH_ALIGNMENT(section_data[i].size, new_nt_header->OptionalHeader.FileAlignment);
      }
    }

    DWORD header_sum;
    DWORD check_sum;
    auto result_headers = CheckSumMappedFile(result.data(), result.size(), &header_sum, &check_sum);
    if (result_headers == nullptr)
    {
      throw std::runtime_error("something goes wrong with winapi(");
    }
    result_headers->OptionalHeader.CheckSum = check_sum;
  }

  HANDLE m_file_h;
  HANDLE m_map_h;

  char* m_file_data;
  IMAGE_DOS_HEADER* m_dos_header;
  IMAGE_NT_HEADERS64* m_nt_header;
  IMAGE_SECTION_HEADER* m_sections;
};


int main(int argc, char** argv)
{
  PEImage source_dll(argv[1]);
  PEImage proxy_dll(argv[2]);

  NewSection section(proxy_dll.make_new_section_rva());

  auto source_exports = source_dll.read_exports();
  auto new_exports_rva = section.append(source_exports, sizeof(IMAGE_EXPORT_DIRECTORY));
  auto new_exports = (IMAGE_EXPORT_DIRECTORY*)section.rva2ptr(new_exports_rva);

  auto dllname = (char*)source_dll.rva2ptr(source_exports->Name);
  new_exports->Name = section.append(dllname, strlen(dllname) + 1);

  new_exports->AddressOfNameOrdinals = section.append(source_dll.rva2ptr(source_exports->AddressOfNameOrdinals), sizeof(DWORD)*new_exports->NumberOfNames);

  new_exports->AddressOfNames = section.expand(sizeof(DWORD)*new_exports->NumberOfNames);
  auto new_names = (DWORD*)section.rva2ptr(new_exports->AddressOfNames);
  auto old_names = (DWORD*)source_dll.rva2ptr(source_exports->AddressOfNames);
  for (size_t i = 0; i < new_exports->NumberOfNames; ++i)
  {
    auto function_name = (char*)source_dll.rva2ptr(old_names[i]);
    new_names[i] = section.append(function_name, strlen(function_name) + 1);
  }

  new_exports->AddressOfFunctions = section.expand(sizeof(DWORD)*new_exports->NumberOfFunctions);
  auto new_functions = (DWORD*)section.rva2ptr(new_exports->AddressOfFunctions);
  for (size_t i = 0; i < new_exports->NumberOfFunctions; ++i)
  {
    std::string new_function_name(argv[4]);
    new_function_name += ".";
    new_function_name += (char*)section.rva2ptr(new_names[i]);
    new_functions[i] = section.append(new_function_name.c_str(), new_function_name.size() + 1);
  }

  std::vector<std::uint8_t> result_binary;
  proxy_dll.merge_export_section(result_binary, section);
  std::ofstream result_dll(argv[3], std::ios::binary);
  result_dll.write((char*)result_binary.data(), result_binary.size());
  return 0;
}