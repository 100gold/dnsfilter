#include "stringproc.h"

#include <codecvt>
#include <algorithm>

#include <Windows.h>


#if (!_DLL) && (_MSC_VER >= 1900 /* VS 2015*/) && (_MSC_VER <= 1911 /* VS 2017 */)
std::locale::id std::codecvt<char32_t, char, _Mbstatet>::id;
#endif


static std::string NFD(const std::string& name)
{
  auto len = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), name.size(), NULL, 0);
  std::wstring s;
  s.resize(len);
  len = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), name.size(), (wchar_t*)s.data(), s.size());
  if (len == 0)
  {
    throw std::runtime_error("MultiByteToWideChar");
  }
  s.resize(len);

  len = NormalizeString(NormalizationD, s.c_str(), s.size(), NULL, 0);
  std::wstring norm_s;
  norm_s.resize(len);
  len = NormalizeString(NormalizationD, s.c_str(), s.size(), (wchar_t*)norm_s.data(), norm_s.size());
  if (len <= 0)
  {
    throw std::runtime_error("NormalizeString");
  }
  norm_s.resize(len);

  len = WideCharToMultiByte(CP_UTF8, 0, norm_s.c_str(), norm_s.size(), NULL, 0, NULL, NULL);
  std::string res;
  res.resize(len);
  len = WideCharToMultiByte(CP_UTF8, 0, norm_s.c_str(), norm_s.size(), (char*)res.data(), res.size(), NULL, NULL);
  if (len == 0)
  {
    throw std::runtime_error("WideCharToMultiByte");
  }
  res.resize(len);
  return res;
}


std::string skeleton(const std::string& name)
{
  std::string s = NFD(name);
  std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> tochar32;

  std::u32string map_s;

  for (char32_t c : tochar32.from_bytes(s))
  {
    map_s += unicode_map_char(c);
  }

  std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> fromchar32;
  return NFD(fromchar32.to_bytes(map_s));
}


IDNNormalForm normalize(const std::string& name)
{
  std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> tochar32;
  std::u32string s = tochar32.from_bytes(name);

  std::u32string token;
  std::vector<std::u32string> tokens;
  std::for_each(s.begin(), s.end(), [&](char32_t c) {
    if (c != U'.')
    {
      token += c;
    }
    else
    {
      if (token.length())
      {
        tokens.push_back(token);
      }
      token.clear();
    }
  });
  if (token.length())
  {
    tokens.push_back(token);
  }

  IDNNormalForm res;
  if (tokens.size() == 0)
  {
    return res;
  }

  auto it = tokens.rbegin();

  res.first_level = *it;
  while (++it != tokens.rend())
  {
    IDNNormalForm::IDNLabel l;
    if (it->size() == 0)
    {
      l.first = '\0';
      l.last = '\0';
      res.other.push_back(l);
      continue;
    }
    else if (s.size() == 1)
    {
      l.first = s[0];
      l.last = '\0';
      res.other.push_back(l);
      continue;
    }

    l.first = s[0];
    l.last = (*it)[it->size() - 1];
    if (it->size() > 2)
    {
      l.middle = it->substr(1, it->size() - 2);
      std::sort(l.middle.begin(), l.middle.end());
    }
    res.other.push_back(l);
  }

  return res;
}