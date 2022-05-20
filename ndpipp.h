#include <iostream>

#include "Packet.h"

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

class nDPIPP
{
private:
    struct ndpi_detection_module_struct *ndpi_struct;

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

public:
    nDPIPP();

    nDPIPP(bool *isSuccess);

    ~nDPIPP();

    // TODO: for each flow and delete all allocations
    void freeWorkflow();

    void ndpi_process_packet(pcpp::RawPacket *packet);
};