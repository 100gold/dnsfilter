#pragma once

#include <string>
#include <vector>
#include <stdint.h>


std::string skeleton(const std::string& name);
std::u32string unicode_map_char(char32_t c);

struct IDNNormalForm
{
  struct IDNLabel
  {
    char32_t first;
    char32_t last;
    std::u32string middle;

    bool operator<(const IDNLabel& rhs) const
    {
      if (first < rhs.first)
      {
        return true;
      }
      if (first > rhs.first)
      {
        return false;
      }

      if (last < rhs.last)
      {
        return true;
      }
      if (last > rhs.last)
      {
        return false;
      }

      return middle < rhs.middle;
    }

    bool operator!=(const IDNLabel& rhs) const
    {
      return !((first == rhs.first) && (last == rhs.last) && (middle == rhs.middle));
    }
  };

  std::u32string first_level;
  std::vector<IDNLabel> other;

  bool operator<(const IDNNormalForm& rhs) const
  {
    if (first_level != rhs.first_level)
    {
      return first_level < rhs.first_level;
    }

    if (other.size() != rhs.other.size())
    {
      return other.size() < rhs.other.size();
    }

    for (size_t i = 0; i < other.size(); ++i)
    {
      if (other[i] != rhs.other[i])
      {
        return other[i] < rhs.other[i];
      }
    }

    return false;
  }
};

IDNNormalForm normalize(const std::string& name);
