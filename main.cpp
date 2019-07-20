#include <pcap.h>
#include <stdio.h>
#include <string.h>

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

char *get_smac(u_char *pkt){
	static char buf[16] = {'\0',};
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", pkt[6], pkt[5], pkt[4], pkt[3], pkt[2], pkt[1]);
	return buf;
}

char *get_dmac(u_char *pkt){
	static char buf[16] = {'\0',};
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", pkt[12], pkt[11], pkt[10], pkt[9], pkt[8], pkt[7]);
	return buf;
}

char *get_sip(u_char *pkt){
	static char buf[16] = {'\0',};
	sprintf(buf,"%d.%d.%d.%d", pkt[26], pkt[27], pkt[28], pkt[29]);
	return buf;
}

char *get_dip(u_char *pkt){
	static char buf[16] = {'\0',};
	sprintf(buf,"%d.%d.%d.%d", pkt[30], pkt[31], pkt[32], pkt[33]);
	return buf;
}

int get_sport(u_char *pkt){
	return (pkt[34]*0x100) + pkt[35];
}

int get_dport(u_char *pkt){
	return (pkt[36]*0x100) + pkt[37];
}

void print_data(u_char *pkt){
	static char buf[0x64] = {'\0',};
	int offset = pkt[46] >> 4 * 4;
	u_char data;
	memcpy(buf, &(pkt[offset + 0x22]), 0x64);
	printf("- Data: [ ");
	
	if (strlen(buf) > 10)
		for(int i = 0; i < 10; i++){
			data = buf[i] & 0xff;
			printf("%02x ", data);
		}
	else
		for(int i = 0; i < strlen(buf); i++){
			data = buf[i] & 0xff;
			printf("%02x ", data);
		}

	printf("]\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	int no = 0;
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		//printf("%u bytes captured\n", header->caplen);
		if (packet[23] == 6) { // When the packet is TCP
			no++;
			printf("\tNo. %d\n", no);
			printf("===================================================\n");
			printf("- Source IP: %s\n", get_sip((u_char *)packet));
			printf("- Source Port: %d\n", get_sport((u_char *)packet));
			printf("- Source Mac: %s\n", get_smac((u_char *)packet));
			printf("- Destination IP: %s\n", get_dip((u_char *)packet));
			printf("- Destination Port: %d\n", get_dport((u_char *)packet));
			printf("- Destination Mac: %s\n", get_dmac((u_char *)packet));
			print_data(((u_char *)packet)); // print data
			printf("===================================================");
			printf("\n\n");
		}else if (packet[12] == 8 && packet[13] == 0) // When the packet is Ethernet
			printf("%s => %s\n\n", get_sip((u_char*)packet), get_dip((u_char*)packet));
	}

	pcap_close(handle);
	return 0;
}
