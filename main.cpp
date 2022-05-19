#include <iostream>
#include "getopt.h"
#include "stdlib.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "PcapLiveDeviceList.h"


#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

struct ndpi_detection_module_struct *ndpi_struct;

void printUsage()
{
    std::cout
        << "-i    :   Port (eth0 or ens1)" << std::endl
        << "--N   :   Number of maximum packets to send in nDPI" << std::endl
        << std::endl;
}

std::string interface;
int maxPackets;

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

void freeWorkflow()
{

    // for each flow
    // delete !!!
}

int main(int argc, char **argv)
{
    processArgs(argc, argv);

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
    if (dev == NULL)
    {
        std::cerr << "Cannot find interface '" << interface << "'" << std::endl;
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

    if (dev->getDnsServers().size() > 0)
        std::cout << "   DNS server:            " << dev->getDnsServers().at(0) << std::endl;
}