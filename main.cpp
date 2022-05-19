#include <iostream>

#include "stdlib.h"
// #include "Packet.h"
// #include "SystemUtils.h"

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

struct ndpi_detection_module_struct* ndpi_struct;

void processArgs(int argc, char **argv)
{

}

int main(int argc, char **argv)
{
    processArgs(argc, argv);

    ndpi_struct = ndpi_init_detection_module(0);

    
}