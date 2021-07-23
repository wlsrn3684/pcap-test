#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void print_mac(const u_char *mac);
void print_ip(const u_char *ip);
void print_port(const u_char *port);
void print_payload(const u_char *payload);

void print_infomation(const u_char *packet);

void usage()
{
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char *argv[])
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
        print_infomation(packet);
    }

    pcap_close(pcap);
}

void print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char *ip)
{
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char *port)
{
    printf("%d\n", ((port[1] & 0xFF00 >> 8) | (port[0] & 0x00FF) << 8));
}

void print_payload(const u_char *payload)
{
    for (int i = 0; i < 8; i++)
    {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

// ETHERNET TYPE -> 12
// PROTOCOL -> 23

// DMAC -> 0
// SMAC -> 6
// SIP -> 26
// DIP -> 30
// SPORT -> 34
// DPORT -> 36
// DATA -> 54

void print_infomation(const u_char *packet)
{
    if ((packet[12] << 8 | packet[13]) == 2048 || packet[23] == 6)
    {
	printf("%d %d\n", (packet[12] << 8 | packet[13]), packet[12]);
        printf("invalid type... (It is not IPv4 or TCP packet)\n\n");
        return;
    }

    printf("DMAC = ");
    print_mac(&packet[0]);
    printf("SMAC = ");
    print_mac(&packet[6]);
    printf("SIP = ");
    print_ip(&packet[12]);
    printf("DIP = ");
    print_ip(&packet[26]);
    printf("SPORT = ");
    print_port(&packet[30]);
    printf("DPORT = ");
    print_port(&packet[36]);
    printf("PAYLOAD = ");
    print_payload(&packet[54]);
    printf("\n");

    return;	
}
