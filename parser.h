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
};