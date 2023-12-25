/*************************
 *     IPK 2019/2020
 * Daša Nosková xnosko05
 *************************/

#include "error.h"
#include "ipk-sniffer.h"
#include "filter.h"


struct argp argp = {options, parse_opt, 0, doc};

int main(int argc, char *argv[])
{
	struct arguments arguments;

	// default values of arguments
	arguments.interface = NULL;
	arguments.port = -1;
	arguments.tcp = false;
	arguments.udp = false;
	arguments.num = 1;

	argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (arguments.interface == NULL) {
        // display all active interfaces
        get_active_interfaces();
        return 0;
    }

    if((arguments.tcp == true && arguments.udp == true) ||
       (arguments.tcp == false && arguments.udp == false)){
        sniff(arguments.interface,arguments.num, arguments.port, "none");}
    else if (arguments.tcp)
        sniff(arguments.interface,arguments.num, arguments.port, "tcp");
    else if (arguments.udp) {
        sniff(arguments.interface,arguments.num, arguments.port, "udp");}


	return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    char *ptr;  //help pointer
    int converted;

    switch (key) {
        case 'i':
            arguments->interface = arg;
            break;
        case 'p':
            converted = strtol(arg,&ptr,10);
            if (converted <= 0 || converted> 655356){
                perror("Port must be number in range <0-655356>.");
                exit(ERR_PARAM);
            }
            arguments->port = strtol(arg,&ptr,10);
            break;
        case 't':
            arguments->tcp = true;
            break;
        case 'u':
            arguments->udp = true;
            break;
        case 'n':
            arguments->num = strtol(arg,&ptr,10);
            if (arguments->num <= 0){
                perror("Number of packets can't be negative.");
                exit(ERR_PARAM);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}


// https://stackoverflow.com/questions/4139405/how-can-i-get-to-know-the-ip-address-for-interfaces-in-c
void get_active_interfaces() {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
        }
    }

    freeifaddrs(ifap);
}
