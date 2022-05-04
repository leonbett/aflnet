#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include "alloc-inl.h"
#include "aflnet.h"

static char *ssh_names[256] = {
    "unknown",
    "DISCONNECT",
    "IGNORE",
    "UNIMPLEMENTED",
    "DEBUG",
    "SERVICE_REQUEST",
    "SERVICE_ACCEPT",
    "EXT_INFO",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "KEXINIT",
    "NEWKEYS",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "KEXDH_INIT / KEX_DH_GEX_REQUEST_OLD / KEX_ECDH_INIT",
    "KEXDH_REPLY / KEX_DH_GEX_GROUP / KEX_ECDH_REPLY",
    "KEX_DH_GEX_INIT",
    "KEX_DH_GEX_REPLY",
    "KEX_DH_GEX_REQUEST",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "USERAUTH_REQUEST",
    "USERAUTH_FAILURE",
    "USERAUTH_SUCCESS",
    "USERAUTH_BANNER",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "USERAUTH_PK_OK / USERAUTH_PASSWD_CHANGEREQ / USERAUTH_INFO_REQUEST",
    "USERAUTH_INFO_RESPONSE",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "GLOBAL_REQUEST",
    "REQUEST_SUCCESS",
    "REQUEST_FAILURE",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "CHANNEL_OPEN",
    "CHANNEL_OPEN_CONFIRMATION",
    "CHANNEL_OPEN_FAILURE",
    "CHANNEL_WINDOW_ADJUST",
    "CHANNEL_DATA",
    "CHANNEL_EXTENDED_DATA",
    "CHANNEL_EOF",
    "CHANNEL_CLOSE",
    "CHANNEL_REQUEST",
    "CHANNEL_SUCCESS",
    "CHANNEL_FAILURE",
};

/* msleep(): Sleep for the requested number of milliseconds. */
int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

#define server_wait_usecs 10000

unsigned int *
(*extract_response_codes)(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) = NULL;
region_t* (*extract_requests)(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref) = NULL;

/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout (ms), default 1
5. Follow-up responses timeout (us), default 1000
*/

unsigned int
get_timestamp(char *path) {
    struct stat attr;
    stat(path, &attr);
    return (unsigned int)attr.st_mtime;
}

void pairlog(char* pair_output_dir, unsigned int timestamp, char* request, char* response_codes) {
    char output_file[512];
    sprintf(output_file, "%s/%s", pair_output_dir, "pairs.csv");
    FILE* fp = NULL;
    fp = fopen(output_file, "a+");
    fprintf(fp, "%u,%s,%s\n", timestamp, request, response_codes);
    fclose(fp);
}

unsigned int
min(unsigned int a, unsigned int b) {
    if(a > b) return b;
    else return a;
}

int
main(int argc, char *argv[]) {
    FILE *fp;
    int portno, n;
    struct sockaddr_in serv_addr;
    char *buf = NULL, *response_buf = NULL;
    int response_buf_size = 0;
    unsigned int size, i, state_count, packet_count = 0;
    unsigned int *state_sequence;
    unsigned int socket_timeout = 1000;
    unsigned int poll_timeout = 1;


    if(argc < 5) {
        PFATAL(
            "Usage: ./aflnet-replay pair_output_dir packet_file protocol port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]");
    }

    char *pair_output_dir = argv[1];

    fp = fopen(argv[2], "rb");

    char **names = NULL;

    if(!strcmp(argv[3], "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
    else if(!strcmp(argv[3], "FTP")) extract_response_codes = &extract_response_codes_ftp;
    else if(!strcmp(argv[3], "DNS")) extract_response_codes = &extract_response_codes_dns;
        //else if (!strcmp(argv[3], "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
    else if(!strcmp(argv[3], "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
    else if(!strcmp(argv[3], "DICOM")) extract_response_codes = &extract_response_codes_dicom;
    else if(!strcmp(argv[3], "SMTP")) extract_response_codes = &extract_response_codes_smtp;
        //else if (!strcmp(argv[3], "SSH")) extract_response_codes = &extract_response_codes_ssh;
    else if(!strcmp(argv[3], "SSH")) {
        extract_response_codes = &extract_response_codes_ssh;
        names = ssh_names;
    } // new mark
    else if(!strcmp(argv[3], "TLS")) extract_response_codes = &extract_response_codes_tls;
    else if(!strcmp(argv[3], "SIP")) extract_response_codes = &extract_response_codes_sip;
    else if(!strcmp(argv[3], "HTTP")) extract_response_codes = &extract_response_codes_http;
    else if(!strcmp(argv[3], "IPP")) extract_response_codes = &extract_response_codes_ipp;
    else if(!strcmp(argv[3], "OPCUA")) extract_response_codes = &extract_response_codes_opcua;
    else {
        fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[3]);
        exit(1);
    }

  if (!strcmp(argv[3], "SSH")) extract_requests = &extract_requests_ssh;
  else if (!strcmp(argv[3], "TLS")) extract_requests = &extract_requests_tls;
  else if (!strcmp(argv[3], "DTLS12")) extract_requests = &extract_requests_dtls12; // not sure if we need tls or dtls12, so including both here.

    portno = atoi(argv[4]);

    if(argc > 5) {
        poll_timeout = atoi(argv[5]);
        if(argc > 6) {
            socket_timeout = atoi(argv[6]);
        }
    }

    //Wait for the server to initialize
    usleep(server_wait_usecs);

    if(response_buf) {
        ck_free(response_buf);
        response_buf = NULL;
        response_buf_size = 0;
    }

    int sockfd;
    if((!strcmp(argv[3], "DTLS12")) || (!strcmp(argv[3], "SIP"))) {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    } else {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }

    if(sockfd < 0) {
        PFATAL("Cannot create a socket");
    }

    //Set timeout for socket data sending/receiving -- otherwise it causes a big delay
    //if the server is still alive after processing all the requests
    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = socket_timeout;

    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        //If it cannot connect to the server under test
        //try it again as the server initial startup time is varied
        for(n = 0; n < 1000; n++) {
            if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
            usleep(1000);
        }
        if(n == 1000) {
            close(sockfd);
            return 1;
        }
    }

    int offsets_responses[1024 * 10];
    int responses = 0;

    int old_response_buf_size = response_buf_size;

    unsigned int BUF_SIZE = 5*1024;
    char* response_codes = malloc(BUF_SIZE);
    memset(response_codes, 0, BUF_SIZE);

    // In my observations, openssh traffic starts with server sending the first packet and client responding.
    // So, we do the matching of command, response pairs in switched order (w.r.t the other evaluated tools).
    // This means, for every "AFLNet packet" (consisting of multiple regions i.e. commands), we proceed as follows:
    // For every region (command) to send, first recv(). Extract the "response codes" from the most recent received S->C packet to "response_codes".
    // Then, send the region (command). Now log the pair: (command, response_codes)
    // Before sending the next region, we will try to recv() again. If there is no data to be received, send the next command, i.e. command_2, and log the pair (command_2, response_codes)
    // As soon as we receive new data, "response_codes" will update. "response_codes" can consist of multiple codes.
    

    while(!feof(fp)) {
        if(buf) {
            ck_free(buf);
            buf = NULL;
        }
        if(fread(&size, sizeof(unsigned int), 1, fp) > 0) {
            packet_count++;
            fprintf(stderr, "\n(Next packet!) Size of the current packet %d is  %d\n", packet_count, size);

            buf = (char *)ck_alloc(size);
            fread(buf, size, 1, fp);

            int old_response_buf_size;

            int n_cmds = 0;
            region_t *regions = (*extract_requests)(buf, size, &n_cmds);

            for(int i = 0; i < n_cmds; ++i) {
              // For every command we send, first receive.
              old_response_buf_size = response_buf_size;
              if(net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) return -8;
              if(response_buf_size > old_response_buf_size) {
                    // Server starts communication, so recv before send.
                    // On receive, set up the new "response_codes".
                    
                    memset(response_codes, 0, BUF_SIZE);

                    int n_return_codes = 0;
                    unsigned int *my_state_sequence;
                    my_state_sequence = (*extract_response_codes)(response_buf + old_response_buf_size,
                                                                  response_buf_size - old_response_buf_size,
                                                                  &n_return_codes);

                    // n_return_codes[0] is always 0.
                    for (int h = 1; h < n_return_codes; h++) {
                      char *name = (names == 0 ? 0 : names[my_state_sequence[h] & 0b11111111]);
                      char* reply = (name == 0) ? "unknown" : name;
                      strcat(response_codes, ":");
                      strcat(response_codes, reply);
                    }
                  
                    fprintf(stderr, "<<< RECV: %s\n", response_codes);

                    offsets_responses[responses++] = old_response_buf_size;
                    old_response_buf_size = response_buf_size;
              }
              else {
                fprintf(stderr, "**** received nothing.\n"); // can happen, no problem.
              }

            int64_t region_size = regions[i].end_byte-regions[i].start_byte+1;
            char *cur_buf = buf + regions[i].start_byte;
            fprintf(stderr, "Sending next region\n");

            n = net_send(sockfd, timeout, cur_buf, region_size);

            //Mark's code
            unsigned int message_count = 0;
            unsigned int *message_sequence = extract_response_codes(cur_buf, region_size, &message_count);
            char *cmd = "unknown";
            if (message_count != 2) {
                fprintf(stderr, "error, message_count must be 2 but is %u\n", message_count);
                return -1;
            }
            int j = 1;
            char *name = (names == 0 ? 0 : names[message_sequence[j] & 0b11111111]);
            cmd = (name == 0) ? "unknown" : name;
            fprintf(stderr, "cmd %u: %s\n", j, cmd);
            ck_free(message_sequence);
            fprintf(stderr,"\n[[[SENT: %s]]]\n", cmd);
            // <\Mark's code>

            // TODO: accumulate cmd's

            if(n != region_size) return -7;

                unsigned int timestamp = get_timestamp(argv[2]);
                // The last command is assigned all response codes. Sometimes, openssh does not send a reply on a command, but after the next command it sends multiple, because it seems to wait on the second command.
                // We match this with the last cmd sent.
                pairlog(pair_output_dir, timestamp, cmd, response_codes);

                msleep(50); // delay required for openssh. 10ms was enough for tinytls?
            }
        }
    }

    fclose(fp);
    close(sockfd);

    //Extract response codes
    state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

    fprintf(stderr, "\n--------------------------------");
    fprintf(stderr, "\nResponses from server:");

    for(i = 0; i < state_count; i++) {
        fprintf(stderr, "%d-", state_sequence[i]);
    }

    fprintf(stderr, "\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
    for(i = 0; i < response_buf_size; i++) {
        fprintf(stderr, "%c", response_buf[i]);
    }
    fprintf(stderr, "\n--------------------------------");

    //Free memory
    ck_free(state_sequence);
    if(buf) ck_free(buf);
    ck_free(response_buf);

    return 0;
}