/*************************
 *     IPK 2019/2020
 * Daša Nosková xnosko05
 *************************/

#include <unistd.h>
#include <argp.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <argz.h>

static char doc [] = "Packet sniffer.";

static struct argp_option options[] = {
        {"tcp", 't', 0,0, "Get only tcp packets."},
        {"udp", 'u', 0,0, "Get only udp packets."},
        {0,'n',"NUM",0,"Show NUM packets."},
        {0, 'i', "INTERFACE",0,"Listen on INTERFACE."},
        {0, 'p', "PORT",0, "Filtering packets on PORT."},
        {0}
};

struct arguments {
    char *interface;
    int port, num;
    bool tcp, udp;
};

/******************** function declarations **********************/

/* Function sets values from command line to arguments */
static error_t parse_opt(int key, char* arg, struct argp_state *state);
/* Function displays all active interfaces. */
void get_active_interfaces();

