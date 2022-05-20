#include "ndpipp.h"

nDPIPP::nDPIPP()
{
}

nDPIPP::nDPIPP(bool *isSuccess)
{

    workflow = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));

    ndpi_struct = ndpi_init_detection_module(0);

    if (ndpi_struct == NULL)
    {
        freeWorkflow();
        std::cerr << "Error in ndpi_init_detection_module" << std::endl;
        *isSuccess = false;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &protos);

    ndpi_finalize_initialization(ndpi_struct);

    *isSuccess = true;
}

nDPIPP::~nDPIPP()
{
    // free all resources
}

// TODO: for each flow and delete all allocations
void nDPIPP::freeWorkflow()
{
}

void nDPIPP::ndpi_process_packet(pcpp::RawPacket *packet)
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
