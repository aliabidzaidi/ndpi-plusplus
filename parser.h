#ifndef PARSER_HEADER
#define PARSER_HEADER

#include <iostream>
#include "Packet.h"
#include "SystemUtils.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"

#include "common.h"

class Parser
{

private:
    std::string printTcpFlags(pcpp::TcpLayer *tcpLayer);

public:
    Parser();
    int parsePacket(pcpp::RawPacket rawPacket);

    bool parsePacket(pcpp::RawPacket *rawPacket,
                     nDPI_flow_info &flow,
                     uint8_t *ip,
                     uint16_t &ip_size,
                     uint16_t &l4_len);
};

#endif // PARSER_HEADER