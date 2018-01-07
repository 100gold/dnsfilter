#include "dnsprotocol.h"

#include <Windows.h>

class BufferReader
{
public:
  BufferReader(const char* src, size_t size)
  {
    m_src = src;
    m_src_size = size;
    m_current = src;
    m_bytes_remaining = size;
  }

  bool read(void* dst, size_t size)
  {
    if (size > m_bytes_remaining)
    {
      return false;
    }
    memcpy(dst, m_current, size);
    m_current += size;
    m_bytes_remaining -= size;

    return true;
  }

  bool read_labels(std::string* s)
  {
    uint8_t label_len;

    s->resize(0);

    do
    {
      if (!read(&label_len, 1))
      {
        return false;
      }

      if (label_len > 0)
      {
        std::string label_part;

        // check for compression (2 hi bits = 11)
        if ((label_len & 0xC0) == 0xC0)
        {
          uint8_t offset_tail;
          if (!read(&offset_tail, 1))
          {
            return false;
          }
          uint16_t offset = label_len;
          offset = ((offset & 0x3F) << 8) + offset_tail;
          if (offset > m_src_size)
          {
            return false;
          }

          const char* save_current = m_current;
          size_t save_bytes_remaining = m_bytes_remaining;
          m_current = m_src + offset;
          m_bytes_remaining = m_src_size - offset;
          if (!read_labels(&label_part))
          {
            return false;
          }
          m_current = save_current;
          m_bytes_remaining = save_bytes_remaining;
          label_len = 0;
        }
        else
        {
          char label_buffer[64]; //63 is real maxlen
          if (read(&label_buffer, label_len))
          {
            return false;
          }
          label_buffer[label_len] = '\0';
          label_part = label_buffer;
        }

        if (s->size() > 0)
        {
          *s += "." + label_part;
        }
        else
        {
          *s = label_part;
        }
      }
    } while (label_len > 0);

    return true;
  }

  size_t get_current_offset() const
  {
    return m_current - m_src;
  }

private:
  const char* m_src;
  size_t m_src_size;
  const char* m_current;
  size_t m_bytes_remaining;
};


bool dns_parse_buffer(const char* buf, size_t len, DNS_RESPONSE* response)
{
  BufferReader b(buf, len);

  if (b.read(&response->header, sizeof(response->header)))
  {
    return false;
  }
  // not dns response
  if (response->header.qr != 1)
  {
    return false;
  }
  // error in response
  if (response->header.rcode != 0)
  {
    return false;
  }

  // no dns answers
  if (response->header.ans_count == 0)
  {
    return false;
  }

  response->queries.resize(0);
  for (size_t i = 0; i < response->header.q_count; ++i)
  {
    DNS_QUERY q;
    if (!b.read_labels(&q.name))
    {
      return false;
    }
    if (!b.read(&q.type, sizeof(q.type)))
    {
      return false;
    }
    if (!b.read(&q.cls, sizeof(q.cls)))
    {
      return false;
    }
    response->queries.push_back(q);
  }

  response->answers.resize(0);
  for (size_t i = 0; i < response->header.ans_count; ++i)
  {
    DNS_ANSWER a;
    if (!b.read_labels(&a.name))
    {
      return false;
    }
    if (!b.read(&a.type, sizeof(a.type)))
    {
      return false;
    }
    if (!b.read(&a.cls, sizeof(a.cls)))
    {
      return false;
    }
    if (!b.read(&a.ttl, sizeof(a.ttl)))
    {
      return false;
    }
    uint16_t rdlength;
    if (!b.read(&rdlength, sizeof(rdlength)))
    {
      return false;
    }
    if (rdlength > 0)
    {
      a.rdata.resize(rdlength);
      a.rdata_offset = b.get_current_offset();
      if (!b.read(a.rdata.data(), a.rdata.size()))
      {
        return false;
      }
    }
    response->answers.push_back(a);
  }

  return true;
}