#include "ndpipp.h"

nDPIPP::nDPIPP()
{
}

nDPIPP::nDPIPP(bool *isSuccess)
{

    // workflow = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));

    // ndpi_struct = ndpi_init_detection_module(0);

    // if (ndpi_struct == NULL)
    // {
    //     freeWorkflow();
    //     std::cerr << "Error in ndpi_init_detection_module" << std::endl;
    //     *isSuccess = false;
    // }

    // NDPI_PROTOCOL_BITMASK protos;
    // NDPI_BITMASK_SET_ALL(protos);
    // ndpi_set_protocol_detection_bitmask2(ndpi_struct, &protos);

    // ndpi_finalize_initialization(ndpi_struct);

    workflow = init_workflow();

    if (workflow == NULL)
    {
        std::cerr << "Error creating workflow " << std::endl;
        *isSuccess = false;
    }
    else
    {
        *isSuccess = true;
    }
}

nDPIPP::~nDPIPP()
{
    // free all resources
}

void nDPIPP::free_workflow()
{
    auto w = workflow;

    if (w == NULL)
    {
        return;
    }

    //   if (w->pcap_handle != NULL)
    //   {
    //     pcap_close(w->pcap_handle);
    //     w->pcap_handle = NULL;
    //   }

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
        // free_workflow(&workflow);
        free_workflow();
        return NULL;
    }

    workflow->total_active_flows = 0;
    workflow->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == NULL)
    {
        // free_workflow(&workflow);
        free_workflow();
        return NULL;
    }

    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
    workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == NULL)
    {
        // free_workflow(&workflow);
        free_workflow();
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    ndpi_finalize_initialization(workflow->ndpi_struct);

    return workflow;
}

// TODO: for each flow and delete all allocations
void nDPIPP::freeWorkflow()
{
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
                    printf("Free fin flow with id %u\n", f->flow_id);
                }
                else
                {
                    printf("Free idle flow with id %u\n", f->flow_id);
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
    // struct nDPI_flow_info *flow_to_process;
    // const struct ndpi_ethhdr *ethernet;
    // const struct ndpi_iphdr *ip;
    // struct ndpi_ipv6hdr *ip6;

    // const uint16_t eth_offset = 0;
    // uint16_t ip_offset;
    // uint16_t ip_size;

    // const uint8_t *l4_ptr = NULL;
    // uint16_t l4_len = 0;

    // uint16_t type;
    // int thread_index = INITIAL_THREAD_HASH; // generated with `dd if=/dev/random bs=1024 count=1 |& hd'

    check_for_idle_flows();

    // uint8_t *ip;
    // uint16_t ip_size;
    // const uint8_t *l4_ptr;
    // uint16_t l4_len;

    pcpp::Packet parsedPacket(packet);
    // Ethernet Layer
    pcpp::EthLayer *ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
        return;
    }
    std::cout << std::endl
              << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
              << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
              << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

    // TODO:  Collect following fields L3 ipv4/ipv6
    // flow.l3_type
    // flow.ip_tuple.v4.src   / v6.src
    // flow.ip_tuple.v4.dst   / v6.dst
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
        std::cout << std::endl
                  << "Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
                  << "Destination IP address: " << ipLayer->getDstIPAddress() << std::endl
                  << "IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::endl
                  << "TTL: " << std::dec << (int)ipLayer->getIPv4Header()->timeToLive << std::endl;

        // ip = (uint8_t *)ipLayer->getIPv4Header();
        // ip_size = (uint16_t)ipLayer->getIPv4Header()->totalLength;
        flow.l3_type = L3_IP;
        flow.ip_tuple.v4.src = ipLayer->getIPv4Header()->ipSrc;
        flow.ip_tuple.v4.dst = ipLayer->getIPv4Header()->ipDst;
    }
    else if (parsedPacket.isPacketOfType(pcpp::IPv6))
    {
        // TODO: ipv6
        flow.l3_type = L3_IP6;
    }
    else
    {
        std::cerr << "A Non IP packet found " << std::endl;
        return;
    }

    // TODO: TCP fields to collect
    // flow.is_midstream_flow
    // flow.flow_fin_ack_seen
    // flow.flow_ack_seen
    // flow.src_port
    // flow.dst_port
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
        std::cout << std::endl
                  << "Source TCP port: " << tcpLayer->getSrcPort() << std::endl
                  << "Destination TCP port: " << tcpLayer->getDstPort() << std::endl
                  << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << std::endl;
        //   << "TCP flags: " << printTcpFlags(tcpLayer) << std::endl;

        const pcpp::tcphdr *t = tcpLayer->getTcpHeader();

        // l4_ptr = (uint8_t *)tcpLayer->getTcpHeader();
        // l4_len = ((uint16_t)tcpLayer->getDataLen());

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
        std::cout << std::endl
                  << "Source UDP port: " << udpLayer->getSrcPort() << std::endl
                  << "Destination UDP port: " << udpLayer->getDstPort() << std::endl
                  << "UDP length: " << pcpp::netToHost16(udpLayer->getUdpHeader()->length) << std::endl;

        // l4_ptr = (uint8_t *)udpLayer->getUdpHeader();
        // l4_len = ((uint16_t)udpLayer->getDataLen());
        // (uint16_t)udpLayer->getUdpHeader()->length;

        const pcpp::udphdr *u = udpLayer->getUdpHeader();

        flow.src_port = u->portSrc;
        flow.src_port = u->portDst;
    }

    // TODO: Discarded tcp/udp flag
    // uint8_t x;
    // std::cout << "nDPI l4 before" << x << "---" << ip << " "  << ip_size << " "  << &l4_ptr << " " << l4_len << std::endl;

    // if (ndpi_detection_get_l4(ip, ip_size, &l4_ptr, &l4_len,
    //                           &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
    // {
    //     fprintf(stderr, "[%8llu] nDPI IPv4/L4 payload detection failed, L4 length: %u\n",
    //             workflow->packets_captured, ip_size);
    //     return;
    // }

    // // std::cout << "nDPI l4 detection returned " << x << "---" << ip << " "  << ip_size << " "  << &l4_ptr << " " << l4_len << std::endl;

    // if(flow.l4_protocol == IPPROTO_TCP){
    //     std::cout << "TCPPPPPPPPPCPPCPCPPCPCPCPPCPCPPCPCP" << std::endl;
    // }
    // else if(flow.l4_protocol == IPPROTO_UDP){
    //     std::cout << "UUUUUUUUUUUDUDUDUUDUDUDUDPUDPUDPUPDUPDDUP" << std::endl;
    // }

    // TODO: 3 Calculate hash based on l4,l3 fields
    // ndpi_flowv4_flow_hash OR ndpi_flowv6_flow_hash
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
    }
    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

    // ndpi_tfind
    hashed_index = flow.hashval % workflow->max_active_flows;

    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);

    if (tree_result == NULL)
    {
        /* flow not found in btree: switch src <-> dst and try to find it again */
    }

    if (tree_result == NULL)
    {
        /* flow still not found, must be new */
    }
}
