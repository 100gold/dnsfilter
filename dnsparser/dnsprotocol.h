#pragma once

#include <string>
#include <list>
#include <vector>
#include <stdint.h>

#pragma pack(push)
#pragma pack(1)
struct DNS_HEADER
{
  uint16_t id; // identification number

  uint8_t rd : 1; // recursion desired
  uint8_t tc : 1; // truncated message
  uint8_t aa : 1; // authoritive answer
  uint8_t opcode : 4; // purpose of message
  uint8_t qr : 1; // query/response flag

  uint8_t rcode : 4; // response code
  uint8_t cd : 1; // checking disabled
  uint8_t ad : 1; // authenticated data
  uint8_t z : 1; // its z! reserved
  uint8_t ra : 1; // recursion available

  uint16_t q_count; // number of question entries
  uint16_t ans_count; // number of answer entries
  uint16_t auth_count; // number of authority entries
  uint16_t add_count; // number of resource entries
};
#pragma pack(pop)

struct DNS_QUERY
{
  std::string name;
  uint16_t type;
  uint16_t cls;
};

struct DNS_ANSWER
{
  std::string name;
  uint16_t type;
  uint16_t cls;
  uint32_t ttl;
  std::vector<uint8_t> rdata;
  size_t rdata_offset;
};

struct DNS_RESPONSE
{
  DNS_HEADER header;
  std::list<DNS_QUERY> queries;
  std::list<DNS_ANSWER> answers;
};

bool dns_parse_buffer(const void* buf, size_t len, DNS_RESPONSE* response);