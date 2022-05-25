#include "ndpipp.h"

uint8_t nDPIPP::maxPackets = 0xFF;

nDPIPP::nDPIPP()
{
}

nDPIPP::nDPIPP(bool &isSuccess)
{
    workflow = init_workflow();

    // this->maxPackets = maxPackets;

    if (workflow == NULL)
    {
        std::cerr << "Error creating workflow " << std::endl;
        isSuccess = false;
    }
    else
    {
        isSuccess = true;
    }
}

nDPIPP::~nDPIPP()
{
    std::cout << "Calling destructor nDPI" << std::endl;
}

void nDPIPP::free_workflow()
{
    auto w = workflow;

    if (w == NULL)
    {
        return;
    }

    if (w->ndpi_struct != NULL)
    {
        ndpi_exit_detection_module(w->ndpi_struct);
    }
    for (size_t i = 0; i < w->max_active_flows; i++)
    {
        ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
    }
    ndpi_free(w->ndpi_flows_active);
    ndpi_free(w->ndpi_flows_idle);
    ndpi_free(w);
    // *workflow = NULL;
}

struct nDPI_workflow *nDPIPP::init_workflow()
{
    struct nDPI_workflow *workflow = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));

    if (workflow == NULL)
    {
        return NULL;
    }

    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (workflow->ndpi_struct == NULL)
    {
        free_workflow();
        return NULL;
    }

    workflow->total_active_flows = 0;
    workflow->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == NULL)
    {
        free_workflow();
        return NULL;
    }

    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
    workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == NULL)
    {
        free_workflow();
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    ndpi_finalize_initialization(workflow->ndpi_struct);

    return workflow;
}

int nDPIPP::ip_tuples_compare(struct nDPI_flow_info const *const A, struct nDPI_flow_info const *const B)
{
    // generate a warning if the enum changes
    switch (A->l3_type)
    {
    case L3_IP:
    case L3_IP6:
        break;
    }

    if (A->l3_type == L3_IP && B->l3_type == L3_IP)
    {
        if (A->ip_tuple.v4.src < B->ip_tuple.v4.src)
        {
            return -1;
        }
        if (A->ip_tuple.v4.src > B->ip_tuple.v4.src)
        {
            return 1;
        }
        if (A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
        {
            return -1;
        }
        if (A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
        {
            return 1;
        }
    }
    else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6)
    {
        if (A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1])
        {
            return -1;
        }
        if (A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1])
        {
            return 1;
        }
        if (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1])
        {
            return -1;
        }
        if (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1])
        {
            return 1;
        }
    }

    if (A->src_port < B->src_port)
    {
        return -1;
    }
    if (A->src_port > B->src_port)
    {
        return 1;
    }
    if (A->dst_port < B->dst_port)
    {
        return -1;
    }
    if (A->dst_port > B->dst_port)
    {
        return 1;
    }

    return 0;
}

int nDPIPP::ndpi_workflow_node_cmp(void const *const A, void const *const B)
{
    struct nDPI_flow_info const *const flow_info_a = (struct nDPI_flow_info *)A;
    struct nDPI_flow_info const *const flow_info_b = (struct nDPI_flow_info *)B;

    if (flow_info_a->hashval < flow_info_b->hashval)
    {
        return (-1);
    }
    else if (flow_info_a->hashval > flow_info_b->hashval)
    {
        return (1);
    }

    /* Flows have the same hash */
    if (flow_info_a->l4_protocol < flow_info_b->l4_protocol)
    {
        return (-1);
    }
    else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol)
    {
        return (1);
    }

    return ip_tuples_compare(flow_info_a, flow_info_b);
}

int nDPIPP::ip_tuple_to_string(struct nDPI_flow_info const *const flow,
                               char *const src_addr_str, size_t src_addr_len,
                               char *const dst_addr_str, size_t dst_addr_len)
{
    switch (flow->l3_type)
    {
    case L3_IP:
        return inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src,
                         src_addr_str, src_addr_len) != NULL &&
               inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst,
                         dst_addr_str, dst_addr_len) != NULL;
    case L3_IP6:
        return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0],
                         src_addr_str, src_addr_len) != NULL &&
               inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],
                         dst_addr_str, dst_addr_len) != NULL;
    }

    return 0;
}

void nDPIPP::ndpi_idle_scan_walker(void const *const A, ndpi_VISIT which, int depth, void *const user_data)
{
    struct nDPI_workflow *const workflow = (struct nDPI_workflow *)user_data;
    struct nDPI_flow_info *const flow = *(struct nDPI_flow_info **)A;

    (void)depth;

    if (workflow == NULL || flow == NULL)
    {
        return;
    }

    if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
            flow->last_seen + MAX_IDLE_TIME < workflow->last_time)
        {
            char src_addr_str[INET6_ADDRSTRLEN + 1];
            char dst_addr_str[INET6_ADDRSTRLEN + 1];
            ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
            workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
            workflow->total_idle_flows++;
        }
    }
}

void nDPIPP::ndpi_flow_info_freer(void *const node)
{
    struct nDPI_flow_info *const flow = (struct nDPI_flow_info *)node;

    ndpi_flow_free(flow->ndpi_flow);
    ndpi_free(flow);
}

void nDPIPP::check_for_idle_flows()
{
    if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time)
    {
        for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index)
        {
            ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);

            while (workflow->cur_idle_flows > 0)
            {
                struct nDPI_flow_info *const f =
                    (struct nDPI_flow_info *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
                if (f->flow_fin_ack_seen == 1)
                {
                    std::cout << "Free fin flow with id " << f->flow_id << std::endl;
                }
                else
                {
                    std::cout << "Free idle flow with id " << f->flow_id << std::endl;
                }
                ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index],
                             ndpi_workflow_node_cmp);
                ndpi_flow_info_freer(f);
                workflow->cur_active_flows--;
            }
        }

        workflow->last_idle_scan_time = workflow->last_time;
    }
}

void nDPIPP::ndpi_process_packet(pcpp::RawPacket *packet)
{
    uint64_t time_ms = (uint64_t)(packet->getPacketTimeStamp().tv_sec) * TICK_RESOLUTION + packet->getPacketTimeStamp().tv_nsec / (1000000000 / TICK_RESOLUTION);

    // std::cout << time_ms << std::endl;

    workflow->packets_captured++;
    workflow->last_time = time_ms;

    struct nDPI_flow_info flow = {};

    size_t hashed_index;
    void *tree_result;
    struct nDPI_flow_info *flow_to_process;
    struct ndpi_ipv6hdr *ip6;

    check_for_idle_flows();

    uint8_t *ip;
    uint16_t ip_size;
    // const uint8_t *l4_ptr;
    uint16_t l4_len;

    pcpp::Packet parsedPacket(packet);
    // Ethernet Layer
    pcpp::EthLayer *ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
        return;
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
            return;
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
        return;
    }
    else
    {
        std::cerr << "A Non IP packet found " << std::endl;
        return;
    }

    if (parsedPacket.isPacketOfType(pcpp::TCP))
    {
        flow.l4_protocol = IPPROTO_TCP;
        // TCP
        pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find TCP layer" << std::endl;
            return;
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
            return;
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

    if (flow.l3_type == L3_IP)
    {
        if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src, flow.ip_tuple.v4.dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst; // fallback
        }
    }
    else if (flow.l3_type == L3_IP6)
    {
        return;
    }
    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

    // ndpi_tfind
    hashed_index = flow.hashval % workflow->max_active_flows;

    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);

    if (tree_result == NULL)
    {
        /* flow not found in btree: switch src <-> dst and try to find it again */
        /* flow not found in btree: switch src <-> dst and try to find it again */
        uint32_t orig_src_ip[4] = {flow.ip_tuple.u32.src[0], flow.ip_tuple.u32.src[1],
                                   flow.ip_tuple.u32.src[2], flow.ip_tuple.u32.src[3]};
        uint32_t orig_dst_ip[4] = {flow.ip_tuple.u32.dst[0], flow.ip_tuple.u32.dst[1],
                                   flow.ip_tuple.u32.dst[2], flow.ip_tuple.u32.dst[3]};
        uint16_t orig_src_port = flow.src_port;
        uint16_t orig_dst_port = flow.dst_port;

        flow.ip_tuple.u32.src[0] = orig_dst_ip[0];
        flow.ip_tuple.u32.src[1] = orig_dst_ip[1];
        flow.ip_tuple.u32.src[2] = orig_dst_ip[2];
        flow.ip_tuple.u32.src[3] = orig_dst_ip[3];

        flow.ip_tuple.u32.dst[0] = orig_src_ip[0];
        flow.ip_tuple.u32.dst[1] = orig_src_ip[1];
        flow.ip_tuple.u32.dst[2] = orig_src_ip[2];
        flow.ip_tuple.u32.dst[3] = orig_src_ip[3];

        flow.src_port = orig_dst_port;
        flow.dst_port = orig_src_port;

        tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);

        flow.ip_tuple.u32.src[0] = orig_src_ip[0];
        flow.ip_tuple.u32.src[1] = orig_src_ip[1];
        flow.ip_tuple.u32.src[2] = orig_src_ip[2];
        flow.ip_tuple.u32.src[3] = orig_src_ip[3];

        flow.ip_tuple.u32.dst[0] = orig_dst_ip[0];
        flow.ip_tuple.u32.dst[1] = orig_dst_ip[1];
        flow.ip_tuple.u32.dst[2] = orig_dst_ip[2];
        flow.ip_tuple.u32.dst[3] = orig_dst_ip[3];

        flow.src_port = orig_src_port;
        flow.dst_port = orig_dst_port;
    }

    if (tree_result == NULL)
    {
        if (workflow->cur_active_flows == workflow->max_active_flows)
        {
            std::cerr << workflow->packets_captured << " max flows to track reached: " << workflow->max_active_flows << ", idle: " << workflow->cur_idle_flows << std::endl;
            return;
        }

        flow_to_process = (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
        if (flow_to_process == NULL)
        {
            std::cerr << workflow->packets_captured << "Not enough memory for flow info\n";
            return;
        }

        memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
        flow_to_process->flow_id = __sync_fetch_and_add(&flow_id, 1);

        flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (flow_to_process->ndpi_flow == NULL)
        {
            std::cerr << workflow->packets_captured << workflow->packets_captured << "Not enough memory for flow struct\n";
            return;
        }
        memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

        std::cout << workflow->packets_captured << "," << flow_to_process->flow_id << " new " << (flow_to_process->is_midstream_flow != 0 ? "midstream-" : "") << " flow\n";
        if (ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL)
        {
            /* Possible Leak, but should not happen as we'd abort earlier. */
            return;
        }

        workflow->cur_active_flows++;
        workflow->total_active_flows++;
    }
    else
    {
        flow_to_process = *(struct nDPI_flow_info **)tree_result;
    }

    flow_to_process->packets_processed++;
    flow_to_process->total_l4_data_len += l4_len;

    if (flow_to_process->first_seen == 0)
    {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;
    /* current packet is an TCP-ACK? */
    flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0)
    {
        flow_to_process->flow_fin_ack_seen = 1;
        std::cout << workflow->packets_captured << "," << flow_to_process->flow_id << "end of flow\n";
    }

    /*
     * This example tries to use maximum supported packets for detection:
     * for uint8: 0xFF
     */
    if (flow_to_process->ndpi_flow->num_processed_pkts == nDPIPP::maxPackets)
    {
        return;
    }
    else if (flow_to_process->ndpi_flow->num_processed_pkts >= nDPIPP::maxPackets - 1)
    {
        /* last chance to guess something, better then nothing */
        uint8_t protocol_was_guessed = 0;
        flow_to_process->guessed_protocol =
            ndpi_detection_giveup(workflow->ndpi_struct,
                                  flow_to_process->ndpi_flow,
                                  1, &protocol_was_guessed);
        if (protocol_was_guessed != 0)
        {
            std::cout << workflow->packets_captured << "," << flow_to_process->flow_id << " [GUESSED] protocol: " << ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.master_protocol) << " app protocol: " << ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.app_protocol) << " category:     " << ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.category) << std::endl;
        }
        else
        {
            std::cout << workflow->packets_captured << "," << flow_to_process->flow_id << " [FLOW NOT CLASSIFIED]\n";
        }
    }

    flow_to_process->detected_l7_protocol =
        ndpi_detection_process_packet(workflow->ndpi_struct, flow_to_process->ndpi_flow,
                                      ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6,
                                      ip_size, time_ms);

    if (ndpi_is_protocol_detected(workflow->ndpi_struct,
                                  flow_to_process->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
            flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
        {
            flow_to_process->detection_completed = 1;
            workflow->detected_flow_protocols++;

            std::cout << workflow->packets_captured << "," << flow_to_process->flow_id << " [DETECTED] protocol: " << ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol) << " app protocol: " << ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol) << " category:  " << ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.category) << std::endl;
        }
    }

    if (flow_to_process->ndpi_flow->num_extra_packets_checked <=
        flow_to_process->ndpi_flow->max_extra_packets_to_check)
    {
    }
}
