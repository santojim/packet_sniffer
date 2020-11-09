// This programm is used to capture packets
// packets are printed in pcap form in file
// It needs super user privileges cause it is
// accessing network devices.
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>


#define SNAPSHOT_LENGTH 65535
#define TOTAL_PACKET_COUNT 0
#define PROMISCUOUS 1



void INThandler(int);

/*globale vars to be sure on SIGINT that pcap file will be closed*/
pcap_t *handle;
pcap_dumper_t *dumpfile;

void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /* save the packet on the dump file */
    pcap_dump(dumpfile, header, pkt_data);
}
// string device flag -i from interface
// string output flag -w from write
// string filter flag -f from filter
int main(int argc, char **argv) {
/* argument parsing starts here*/
/*------------------------------------------------------------------*/
    int c;
    char *device = NULL;
    char *input_filter= NULL;
    char *output_filename = "output_file.pcap";
    int mandatory_args=0;
     while ((c = getopt (argc, argv, "hi:w:f:")) != -1)
       switch (c)
         {
         case 'i':
           device = optarg;
           mandatory_args++;
           break;
         case 'w':
           output_filename = optarg;
           break;
         case 'f':
           input_filter = optarg;
           break;
         case 'h':
           printf("Usage: %s [OPTIONS]\n", argv[0]);
           printf("  -i interface \n");
           printf("  -w file to write output (default is output_file.pcap and is placed\
 in the same directory with executable)\n");
           printf("  -f filter should be in this format -> -f \"port 80 or port 8080\" etc...\n");
           printf("\n");
           return(0);
         case '?':
           if (optopt == 'f' ||optopt == 'i'|| optopt == 'w'  )
             fprintf (stderr, "Option -%c requires an argument.\n", optopt);
           else if (isprint (optopt))
             fprintf (stderr, "Unknown option `-%c'.\n", optopt);
           else
             fprintf (stderr,
                      "Unknown option character `\\x%x'.\n",optopt);
           return 1;
         default:
           printf("Usage: %s [OPTIONS]\n", argv[0]);
           printf("  -i interface \n");
           printf("  -w file to write output (default is output_file.pcap and is placed\
 in the same directory with executable)\n");
           printf("  -f filter should be in this format -> -f \"port 80 or port 8080\" etc...\n");
           printf("\n");
           return(0);
         }
    if (mandatory_args < 1){
           printf("-i [device] is mandatory \n");
           printf("Usage: %s [OPTIONS]\n", argv[0]);
           printf("  -i interface \n");
           printf("  -w file to write output (default is output_file.pcap and is placed\
 in the same directory with executable)\n");
           printf("  -f filter should be in this format -> -f \"port 80 or port 8080\" etc...\n");
           printf("\n");
           return(0);
    }
/*------------------------------------------------------------------*/
/* argument parsing ends here*/
    /* signal handler */
    signal(SIGINT, INThandler);

    char error_buffer[PCAP_ERRBUF_SIZE];
    /*filter*/
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;
    if (pcap_lookupnet(device, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
        exit(1);
    }
    /* Here starts the main pcap function calls as mentioned in pcap man page*/
    /* pcap_create -> pcap_set_timeout -> pcap_set_promisc -> pcap_set_snaplen -> */
    /* pcap_compile & pcap_setfilter for filters -> pcap_dump_open -> pcap_loop -> */
    /* pcap_close & pcap_dump_close */
    handle = pcap_create(device,error_buffer);
    if (handle == NULL ){
      sprintf(error_buffer, "pcap_create for %s failed\n",device);
      pcap_perror(handle,error_buffer);
      exit(1);
    }
    if ( pcap_set_timeout(handle,1) != 0 ) {
      sprintf(error_buffer, "pcap_set_timeout failed\n");
      pcap_perror(handle,error_buffer);
      pcap_close(handle);
      exit(1);
    }
    if ( pcap_set_promisc (handle,PROMISCUOUS) != 0 ) {// TODO check how to check if in promiscous mode
      sprintf(error_buffer, "pcap_set_promisc failed\n");
      pcap_perror(handle,error_buffer);
      pcap_close(handle);
      exit(1);
    }
    pcap_set_snaplen (handle,SNAPSHOT_LENGTH);
    if ( pcap_activate(handle) != 0) { // pcap_activate returns zero on success
      sprintf(error_buffer, "pcap_activate failed\n");
      pcap_perror(handle,error_buffer);
      pcap_close(handle);
      exit(1);
    }
    if (pcap_compile(handle, &filter, input_filter, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    /* Open the dump file */
    dumpfile = pcap_dump_open(handle, output_filename);
    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }
    printf("\nlistening on %s ... Press Ctrl+C to stop...\n", device);
    /* End the loop after this many packets are captured */
//    pcap_loop(handle, total_packet_count, &packet_handler, (unsigned char *)dumpfile);
//    A value of -1 or 0 for cnt is equivalent to infinity
    if ( pcap_loop(handle, TOTAL_PACKET_COUNT, &packet_handler, (unsigned char *)dumpfile) < 0) {
            /*
             * Print out appropriate text, followed by the error message
             * generated by the packet capture library.
             */
            sprintf(error_buffer,"Error reading packets from interface %s",device);
            pcap_perror(handle,error_buffer);
            exit(1);
    }

    return 0;
}

void  INThandler(int sig)
{
    signal(sig, SIG_IGN);
    pcap_close(handle);
    pcap_dump_close(dumpfile);
    exit(0);
}
// The below links were used to create above code
//https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c
//https://www.devdungeon.com/content/using-libpcap-c
//https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut7.html
