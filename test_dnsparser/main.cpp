#include <stdio.h>
#include <sstream>

#include "../dnsparser/dnsprotocol.h"
#include "../dnsparser/stringproc.h"

using namespace std::string_literals;


bool test_stringproc()
{
  //Cyrrilic 'o'
  if (skeleton("\xD0\xBE\xD0\xBE\x6C\x6C") != std::string("ooll"))
  { 
    return false;
  }

  if (skeleton("\x58\x6C\xC5\x93") != std::string("Xloe"))
  {
    return false;
  }

  auto nm = normalize("organization.org");
  if (nm.first_level != U"org")
  {
    return false;
  }
  if (nm.other.size() != 1)
  {
    return false;
  }
  if (nm.other[0].first != U'o')
  {
    return false;
  }
  if (nm.other[0].last != U'n')
  {
    return false;
  }
  if (nm.other[0].middle != U"aagiinortz")
  {
    return false;
  }

  return true;
}


bool test_parser(DnsParser& dns)
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
  if (!dns.parse_buffer(buffer, sizeof(buffer), &response))
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


bool test_checker(DnsParser& dns)
{
  DNS_QUERY default_query{ "organization.org", 1, 1 };

  {
    DNS_RESPONSE resp;
    resp.queries.push_back(default_query);
    resp.answers.emplace_back(DNS_ANSWER{ "organization.org", 1, 1, 0,{ 0,0,0,0 }, 0 });
    if (dns.check_for_reaction(resp))
    {
      return false;
    }
  }

  {
    DNS_RESPONSE resp;
    resp.queries.push_back(default_query);
    resp.answers.emplace_back(DNS_ANSWER{ "orgainzation.org", 1, 1, 0,{ 0,0,0,0 }, 0 });
    if (!dns.check_for_reaction(resp))
    {
      return false;
    }
  }

  //"orgаnization.org" with Cyrrilic 'a'
  {
    DNS_RESPONSE resp;
    resp.queries.push_back(default_query);
    resp.answers.emplace_back(DNS_ANSWER{ "\x6F\x72\x67\xD0\xB0\x6E\x69\x7A\x61\x74\x69\x6F\x6E\x2E\x6F\x72\x67", 1, 1, 0,{ 0,0,0,0 }, 0 });
    if (!dns.check_for_reaction(resp))
    {
      return false;
    }
  }

  {
    DNS_RESPONSE resp;
    resp.queries.push_back(DNS_QUERY{ "example.com", 1, 1 });
    resp.answers.emplace_back(DNS_ANSWER{ "example.com", 1, 1, 0,{ 0,0,0,0 }, 0 });
    if (dns.check_for_reaction(resp))
    {
      return false;
    }
  }

  return true;
}


//TODO: use boost::test
int main(int argc, char** argv)
{
  DnsParser dns;

  if (!test_stringproc())
  {
    printf("test_stringproc fail\n");
    return 1;
  }

  if (!test_parser(dns))
  {
    printf("test_parser fail\n");
    return 1;
  }

  if (!test_checker(dns))
  {
    printf("test_checker fail\n");
    return 1;
  }

  printf("test done.\n");
  return 0;
}