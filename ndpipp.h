#include <iostream>

#include "Packet.h"
#include "SystemUtils.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"

#include <ndpi_main.h>
#include <ndpi_typedefs.h>

#ifndef NDPI_TYPES_INCLUDES
#define NDPI_TYPES_INCLUDES
#include <ndpi_api.h>

#endif

#include "common.h"
#include "parser.h"

class nDPIPP
{
private:
    struct ndpi_detection_module_struct *ndpi_struct;

    struct nDPI_workflow *workflow;

public:
    static uint8_t maxPackets;

    nDPIPP();

    nDPIPP(bool &isSuccess);

    ~nDPIPP();

    void free_workflow();

    struct nDPI_workflow *init_workflow();

    static int ip_tuple_to_string(struct nDPI_flow_info const *const flow,
                                  char *const src_addr_str, size_t src_addr_len,
                                  char *const dst_addr_str, size_t dst_addr_len);

    static int ip_tuples_compare(struct nDPI_flow_info const *const A, struct nDPI_flow_info const *const B);

    static int ndpi_workflow_node_cmp(void const *const A, void const *const B);

    static void ndpi_idle_scan_walker(void const *const A, ndpi_VISIT which, int depth, void *const user_data);

    static void ndpi_flow_info_freer(void *const node);

    void check_for_idle_flows();

    void ndpi_process_packet(pcpp::RawPacket *packet);

    static void ndpi_print_flow(void const *const A, ndpi_VISIT which, int depth, void *const user_data);

    void print_stats();
};