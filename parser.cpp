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


