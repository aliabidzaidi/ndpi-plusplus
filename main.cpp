#include <iostream>
#include "getopt.h"
#include "stdlib.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

struct ndpi_detection_module_struct *ndpi_struct;
std::string interface;
int maxPackets;

/**
 * A struct for collecting packet statistics
 */
struct PacketStats
{
    int ethPacketCount;
    int ipv4PacketCount;
    int ipv6PacketCount;
    int tcpPacketCount;
    int udpPacketCount;
    int dnsPacketCount;
    int httpPacketCount;
    int sslPacketCount;

    /**
     * Clear all stats
     */
    void clear()
    {
        ethPacketCount = 0;
        ipv4PacketCount = 0;
        ipv6PacketCount = 0;
        tcpPacketCount = 0;
        udpPacketCount = 0;
        tcpPacketCount = 0;
        dnsPacketCount = 0;
        httpPacketCount = 0;
        sslPacketCount = 0;
    }

    /**
     * C'tor
     */
    PacketStats() { clear(); }

    /**
     * Collect stats from a packet
     */
    void consumePacket(pcpp::Packet &packet)
    {
        if (packet.isPacketOfType(pcpp::Ethernet))
            ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4))
            ipv4PacketCount++;
        if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP))
            tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
            dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL))
            sslPacketCount++;
    }

    /**
     * Print stats to console
     */
    void printToConsole()
    {
        std::cout
            << "Ethernet packet count: " << ethPacketCount << std::endl
            << "IPv4 packet count:     " << ipv4PacketCount << std::endl
            << "IPv6 packet count:     " << ipv6PacketCount << std::endl
            << "TCP packet count:      " << tcpPacketCount << std::endl
            << "UDP packet count:      " << udpPacketCount << std::endl
            << "DNS packet count:      " << dnsPacketCount << std::endl
            << "HTTP packet count:     " << httpPacketCount << std::endl
            << "SSL packet count:      " << sslPacketCount << std::endl;
    }
};

PacketStats stats;
#define TICK_RESOLUTION 1000

enum nDPI_l3_type
{
    L3_IP,
    L3_IP6
};

struct nDPI_flow_info
{
    uint32_t flow_id;
    unsigned long long int packets_processed;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t hashval;

    enum nDPI_l3_type l3_type;
    union
    {
        struct
        {
            uint32_t src;
            uint32_t pad_00[3];
            uint32_t dst;
            uint32_t pad_01[3];
        } v4;
        struct
        {
            uint64_t src[2];
            uint64_t dst[2];
        } v6;

        struct
        {
            uint32_t src[4];
            uint32_t dst[4];
        } u32;
    } ip_tuple;

    unsigned long long int total_l4_data_len;
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t is_midstream_flow : 1;
    uint8_t flow_fin_ack_seen : 1;
    uint8_t flow_ack_seen : 1;
    uint8_t detection_completed : 1;
    uint8_t tls_client_hello_seen : 1;
    uint8_t tls_server_hello_seen : 1;
    uint8_t flow_info_printed : 1;
    uint8_t reserved_00 : 1;
    uint8_t l4_protocol;

    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_protocol;

    struct ndpi_flow_struct *ndpi_flow;
};

struct nDPI_workflow
{
    pcap_t *pcap_handle;

    volatile long int error_or_eof;

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_l4_data_len;
    unsigned long long int detected_flow_protocols;

    uint64_t last_idle_scan_time;
    uint64_t last_time;

    void **ndpi_flows_active;
    unsigned long long int max_active_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int total_active_flows;

    void **ndpi_flows_idle;
    unsigned long long int max_idle_flows;
    unsigned long long int cur_idle_flows;
    unsigned long long int total_idle_flows;

    struct ndpi_detection_module_struct *ndpi_struct;
};

struct nDPI_workflow *workflow;

void printUsage()
{
    std::cout
        << "-i    :   Port (eth0 or ens1)" << std::endl
        << "--N   :   Number of maximum packets to send in nDPI" << std::endl
        << std::endl;
}

void processArgs(int argc, char **argv)
{
    const char *const short_opts = "i:Nh";
    const option long_opts[] = {
        {"i", required_argument, nullptr, 'i'},
        {"N", required_argument, nullptr, 'N'},
        {0, 0, 0, 0}
        // {"", optional_argument, 0, ''},
    };

    while (true)
    {
        const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);

        if (-1 == opt)
            break;

        switch (opt)
        {
        case 'i':
            interface = std::string(optarg);
            std::cout << "Input port set to: " << interface << std::endl;
            break;

        case 'N':
            maxPackets = std::stoi(optarg);
            std::cout << "Maximum packets to send in nDPI set to: " << maxPackets << std::endl;
            break;

        case 'h': // -h or --help
        case '?': // Unrecognized option
        default:
            printUsage();
            break;
        }
    }
}

// TODO: for each flow and delete all allocations
void freeWorkflow()
{
}

std::string printTcpFlags(pcpp::TcpLayer *tcpLayer)
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

int parsePacket(pcpp::RawPacket rawPacket)
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
    else if(parsedPacket.isPacketOfType(pcpp::UDP))
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

void ndpi_process_packet(pcpp::RawPacket *packet)
{
    uint64_t time_ms = (uint64_t)(packet->getPacketTimeStamp().tv_sec) * TICK_RESOLUTION + packet->getPacketTimeStamp().tv_nsec / (1000000000 / TICK_RESOLUTION);

    std::cout << time_ms << std::endl;

    // struct nDPI_workflow *workflow;
    // struct nDPI_flow_info flow = {};

    workflow->packets_captured++;
    workflow->last_time = time_ms;

    // size_t hashed_index;
    // void *tree_result;
    // struct nDPI_flow_info *flow_to_process;

    // check for idle workflows

    parsePacket(*packet);

    // Collect packet detials
    // L2 + L3 + L4
    // ip header
    // ip size
    // time

    // ndpi_detection_get_l4
    // ip4 or ip6

    // tree_result = ndpi_tfind(flow, activeFlows, fn node_cmp)

    // tree_result == NULL if flow not found
    // switch src<-->dst
    // ndpi_tfind again

    // if tree_result == NULL
    // checks such as max_active_flows,
    // create to new flow (ndpi_malloc())

    // ndpi_tsearch ???

    // struct ndpi_proto l7_protocol = ndpi_detection_process_packet(
    //     ndpi_struct, // ndpi_struct
    //     // ndpi_flow
    //     // iph
    //     // ipsize
    //     // time
    //     // src
    //     // dst
    // );
}

/**
 * A callback function for the async capture which is called each time a packet is captured
 */
static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
    // extract the stats object form the cookie
    PacketStats *stats = (PacketStats *)cookie;

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    // collect stats from packet
    stats->consumePacket(parsedPacket);

    ndpi_process_packet(packet);
}

int main(int argc, char **argv)
{
    processArgs(argc, argv);

    workflow = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));

    ndpi_struct = ndpi_init_detection_module(0);

    if (ndpi_struct == NULL)
    {
        freeWorkflow();
        std::cerr << "Error in ndpi_init_detection_module" << std::endl;
        return 1;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &protos);

    ndpi_finalize_initialization(ndpi_struct);

    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface);
    if (dev == NULL || !dev->open())
    {
        std::cerr << "Cannot find or open interface '" << interface << "'" << std::endl;
        return 1;
    }

    // before capturing packets let's print some info about this interface
    std::cout
        << "Interface info:" << std::endl
        << "   Interface name:        " << dev->getName() << std::endl           // get interface name
        << "   Interface description: " << dev->getDesc() << std::endl           // get interface description
        << "   MAC address:           " << dev->getMacAddress() << std::endl     // get interface MAC address
        << "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
        << "   Interface MTU:         " << dev->getMtu() << std::endl;           // get interface MTU

    // if (dev->getDnsServers().size() > 0)
    //     std::cout << "   DNS server:            " << dev->getDnsServers().at(0) << std::endl;

    std::cout << "Starting async capture..." << std::endl;

    // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
    dev->startCapture(onPacketArrives, &stats);

    // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
    pcpp::multiPlatformSleep(5);

    // stop capturing packets
    dev->stopCapture();

    // print results
    std::cout << "Results:" << std::endl;
    stats.printToConsole();
}