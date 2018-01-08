#include <stdio.h>

#include "../dnsparser/dnsprotocol.h"


bool test1()
{
  uint8_t buffer[] = {
    0x28, 0xd9, 0x85, 0x80, 0x00, 0x01, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x0e, 0x68, 0x6f, 0x6d,
    0x65, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x32,
    0x30, 0x30, 0x38, 0x02, 0x72, 0x75, 0x00, 0x00,
    0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0xc0,
    0xa8, 0x2d, 0x2b, 0xc0, 0x0c, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0xc0,
    0xa8, 0x37, 0x89
  };

  DNS_RESPONSE response;
  if (!dns_parse_buffer(buffer, sizeof(buffer), &response))
  {
    return false;
  }

  if (response.queries.size() != 1)
  {
    return false;
  }

  if (response.queries.front().name != "homedomain2008.ru")
  {
    return false;
  }

  if (response.answers.size() != 2)
  {
    return false;
  }

  if (response.answers.front().name != "homedomain2008.ru")
  {
    return false;
  }

  if (response.answers.front().type != 1)
  {
    return false;
  }

  if (response.answers.front().rdata_offset != 47)
  {
    return false;
  }

  return true;
}


//TODO: use boost::test
int main(int argc, char** argv)
{
  if (!test1())
  {
    printf("test1 fail\n");
    return 1;
  }
  printf("test done.\n");
  return 0;
}