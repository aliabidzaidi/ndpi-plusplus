#ifndef PARSER_IMPLEMENTS
#define PARSER_IMPLEMENTS

#include "parser.h"

Parser::Parser()
{
    // Do something here rather
}

std::string Parser::printTcpFlags(pcpp::TcpLayer *tcpLayer)
{
    std::string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";

    return result;
}

int Parser::parsePacket(pcpp::RawPacket rawPacket)
{
    pcpp::Packet parsedPacket(&rawPacket);

    // Ethernet Layer
    pcpp::EthLayer *ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
        return 1;
    }
    std::cout << std::endl
              << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
              << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
              << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {

        // IP Layer
        pcpp::IPv4Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
            return 1;
        }

        // print source and dest IP addresses, IP ID and TTL
        std::cout << std::endl
                  << "Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
                  << "Destination IP address: " << ipLayer->getDstIPAddress() << std::endl
                  << "IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::endl
                  << "TTL: " << std::dec << (int)ipLayer->getIPv4Header()->timeToLive << std::endl;
    }

    if (parsedPacket.isPacketOfType(pcpp::TCP))
    {
        // TCP
        pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find TCP layer" << std::endl;
            return 1;
        }

        // print TCP source and dest ports, window size, and the TCP flags that are set in this layer
        std::cout << std::endl
                  << "Source TCP port: " << tcpLayer->getSrcPort() << std::endl
                  << "Destination TCP port: " << tcpLayer->getDstPort() << std::endl
                  << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << std::endl
                  << "TCP flags: " << printTcpFlags(tcpLayer) << std::endl;
    }
    else if (parsedPacket.isPacketOfType(pcpp::UDP))
    {
        // UDP Layer
        pcpp::UdpLayer *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
        if (udpLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find UDP Layer" << std::endl;
            return 1;
        }

        // print TCP source and dest ports, window size, and the TCP flags that are set in this layer
        std::cout << std::endl
                  << "Source UDP port: " << udpLayer->getSrcPort() << std::endl
                  << "Destination UDP port: " << udpLayer->getDstPort() << std::endl
                  << "UDP length: " << pcpp::netToHost16(udpLayer->getUdpHeader()->length) << std::endl;
    }

    return 0;
}

bool Parser::parsePacket(pcpp::RawPacket *rawPacket,
                         nDPI_flow_info &flow,
                         uint8_t *ip,
                         uint16_t &ip_size,
                         uint16_t &l4_len)
{

    pcpp::Packet parsedPacket(rawPacket);
    // Ethernet Layer
    pcpp::EthLayer *ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
        return false;
    }
    // std::cout << std::endl
    //           << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
    //           << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
    //           << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // IP Layer
        pcpp::IPv4Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
            return false;
        }

        // print source and dest IP addresses, IP ID and TTL
        // std::cout << std::endl
        //           << "Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
        //           << "Destination IP address: " << ipLayer->getDstIPAddress() << std::endl
        //           << "IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::endl
        //           << "TTL: " << std::dec << (int)ipLayer->getIPv4Header()->timeToLive << std::endl;

        ip = (uint8_t *)ipLayer->getIPv4Header();
        ip_size = (uint16_t)ipLayer->getIPv4Header()->totalLength;
        flow.l3_type = L3_IP;
        flow.ip_tuple.v4.src = ipLayer->getIPv4Header()->ipSrc;
        flow.ip_tuple.v4.dst = ipLayer->getIPv4Header()->ipDst;
    }
    else if (parsedPacket.isPacketOfType(pcpp::IPv6))
    {
        // TODO: ipv6
        flow.l3_type = L3_IP6;
        std::cout << "Flow is IPv6 return " << std::endl;
        return false;
    }
    else
    {
        std::cerr << "A Non IP packet found " << std::endl;
        return false;
    }

    if (parsedPacket.isPacketOfType(pcpp::TCP))
    {
        flow.l4_protocol = IPPROTO_TCP;
        // TCP
        pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find TCP layer" << std::endl;
            return false;
        }

        // print TCP source and dest ports, window size, and the TCP flags that are set in this layer
        // std::cout << std::endl
        //           << "Source TCP port: " << tcpLayer->getSrcPort() << std::endl
        //           << "Destination TCP port: " << tcpLayer->getDstPort() << std::endl
        //           << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << std::endl;
        //   << "TCP flags: " << printTcpFlags(tcpLayer) << std::endl;

        const pcpp::tcphdr *t = tcpLayer->getTcpHeader();

        // l4_ptr = (uint8_t *)tcpLayer->getTcpHeader();
        l4_len = ((uint16_t)tcpLayer->getDataLen());

        flow.is_midstream_flow = t->synFlag == 0 ? 1 : 0;
        flow.flow_fin_ack_seen = (t->finFlag == 1 && t->ackFlag == 1 ? 1 : 0);
        flow.flow_ack_seen = t->ackFlag;
        flow.src_port = t->portSrc;
        flow.src_port = t->portDst;
    }
    // TODO: Collect UDP fields
    // flow.src_port
    // flow.dst_port
    else if (parsedPacket.isPacketOfType(pcpp::UDP))
    {
        flow.l4_protocol = IPPROTO_UDP;
        // UDP Layer
        pcpp::UdpLayer *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
        if (udpLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find UDP Layer" << std::endl;
            return false;
        }

        // print TCP source and dest ports, window size, and the TCP flags that are set in this layer
        // std::cout << std::endl
        //           << "Source UDP port: " << udpLayer->getSrcPort() << std::endl
        //           << "Destination UDP port: " << udpLayer->getDstPort() << std::endl
        //           << "UDP length: " << pcpp::netToHost16(udpLayer->getUdpHeader()->length) << std::endl;

        // l4_ptr = (uint8_t *)udpLayer->getUdpHeader();
        l4_len = ((uint16_t)udpLayer->getDataLen());

        const pcpp::udphdr *u = udpLayer->getUdpHeader();

        flow.src_port = u->portSrc;
        flow.src_port = u->portDst;
    }

    return true;
}

#endif