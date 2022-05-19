#include <iostream>

#include "stdlib.h"
// #include "Packet.h"
// #include "SystemUtils.h"

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

struct ndpi_detection_module_struct *ndpi_struct;

void processArgs(int argc, char **argv)
{
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
}