#include <stdio.h>
#include <time.h>
#include <errno.h>    
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include "alloc-inl.h"
#include "aflnet.h"
// new version 27.04.22


// This is the one im using.

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;
region_t* (*extract_requests)(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref) = NULL;


/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout (ms), default 1
5. Follow-up responses timeout (us), default 1000
*/

unsigned int get_timestamp(char *path) {
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

unsigned int min(unsigned int a, unsigned int b) {
	if (a>b) return b;
	else return a;
}

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

long long timeInMilliseconds(void) {
    struct timeval tv;

    gettimeofday(&tv,NULL);
    return (((long long)tv.tv_sec)*1000)+(tv.tv_usec/1000);
}

int main(int argc, char* argv[])
{
  FILE *fp;
  int portno, n;
  struct sockaddr_in serv_addr;
  char* buf = NULL, *response_buf = NULL;
  int response_buf_size = 0;
  unsigned int size, i, state_count, packet_count = 0;
  unsigned int *state_sequence;
  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;


  if (argc < 5) {
    PFATAL("Usage: ./aflnet-replay pair_output_dir packet_file protocol port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]");
  }

  char* pair_output_dir = argv[1];

  fp = fopen(argv[2],"rb");

  if (!strcmp(argv[3], "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
  else if (!strcmp(argv[3], "FTP")) extract_response_codes = &extract_response_codes_ftp;
  else if (!strcmp(argv[3], "DNS")) extract_response_codes = &extract_response_codes_dns;
  else if (!strcmp(argv[3], "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
  else if (!strcmp(argv[3], "DICOM")) extract_response_codes = &extract_response_codes_dicom;
  else if (!strcmp(argv[3], "SMTP")) extract_response_codes = &extract_response_codes_smtp;
  else if (!strcmp(argv[3], "SSH")) extract_response_codes = &extract_response_codes_ssh;
  else if (!strcmp(argv[3], "TLS")) extract_response_codes = &extract_response_codes_tls;
  else if (!strcmp(argv[3], "SIP")) extract_response_codes = &extract_response_codes_sip;
  else if (!strcmp(argv[3], "HTTP")) extract_response_codes = &extract_response_codes_http;
  else if (!strcmp(argv[3], "IPP")) extract_response_codes = &extract_response_codes_ipp;
  else if (!strcmp(argv[3], "OPCUA")) extract_response_codes = &extract_response_codes_opcua;
  else {fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[3]); exit(1);}

  if (!strcmp(argv[3], "RTSP")) extract_requests = &extract_requests_rtsp;
  else if (!strcmp(argv[3], "FTP")) extract_requests = &extract_requests_ftp;
  else if (!strcmp(argv[3], "SSH")) extract_requests = &extract_requests_ssh;
  else if (!strcmp(argv[3], "TLS")) extract_requests = &extract_requests_tls;
  else if (!strcmp(argv[3], "DTLS12")) extract_requests = &extract_requests_dtls12; // not sure if we need tls or dtls12, so including both here.
  else if (!strcmp(argv[3], "SMTP")) extract_requests = &extract_requests_smtp;
  //TODO: also do this in opensshtinytls.c

  portno = atoi(argv[4]);

  if (argc > 5) {
    poll_timeout = atoi(argv[5]);
    if (argc > 6) {
      socket_timeout = atoi(argv[6]);
    }
  }

  //Wait for the server to initialize
  usleep(server_wait_usecs);

  if (response_buf) {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  int sockfd;
  if ((!strcmp(argv[3], "DTLS12")) || (!strcmp(argv[3], "SIP"))) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  } else {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

  if (sockfd < 0) {
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
    for (n=0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
      usleep(1000);
    }
    if (n== 1000) {
      close(sockfd);
      return 1;
    }
  }

  int offsets_responses[1024*10];
  int official_requests = 0;
  int responses = 0;
  int no_responses= 0;

  int ctr = 0;
  int old_response_buf_size = response_buf_size;
    if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) {fprintf(stderr, "wtf\n"); return 1;}//break;
    if (response_buf_size > old_response_buf_size) {
      // Received something
      // TODO: Maybe do some checks/matching here.

      fprintf(stderr, "initial receive\n"); // eat some initial data befre the loop here

      offsets_responses[responses++] = old_response_buf_size;
      old_response_buf_size = response_buf_size;
    }
  

  //Send requests one by one
  //And save all the server responses
  while(!feof(fp)) {
    if (buf) {ck_free(buf); buf = NULL;}
    if (fread(&size, sizeof(unsigned int), 1, fp) > 0) {
      packet_count++;
      fprintf(stderr,"\nSize of the current packet (replayable chunk) %d is  %d\n", packet_count, size);

      official_requests++;

      buf = (char *)ck_alloc(size);
      fread(buf, size, 1, fp);

      // Initial recv.
      old_response_buf_size = response_buf_size;
      if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
      if (response_buf_size > old_response_buf_size) {
        fprintf(stderr, "shouldn't recv here.\n");
        return 1;
      }

      int n_cmds = 0;
      region_t* regions = (*extract_requests)(buf, size, &n_cmds);
      char szOutputFile[512];
      sprintf(szOutputFile, "/tmp/regions%d", ctr);
      save_regions_to_file(regions, n_cmds, szOutputFile);
      ++ctr;

      // Send all "regions" of replayable test case separately
      for (int i = 0; i < n_cmds; i++) {
        int64_t region_size = regions[i].end_byte-regions[i].start_byte+1;
        fprintf(stderr, "--------------------------------------------------------\n");

        fprintf(stderr, "send region %d: from pos %lld length %lld\n", i, regions[i].start_byte, region_size);
        //fprintf(stderr, "send buffer: %*s\n", (int)size, buf+regions[i].start_byte);
        fprintf(stderr, "send buffer: ");
        fwrite(buf+regions[i].start_byte, sizeof(char), (int)region_size, stderr);
        fprintf(stderr, "\n");

        fprintf(stderr, "hex: ");
        for (int j=0; j < region_size; j++) {
          fprintf(stderr, "%.2x ", buf[regions[i].start_byte + j] & 0xff);
        }
        fprintf(stderr, "\n");

        n = net_send(sockfd, timeout, buf + regions[i].start_byte, region_size);

        old_response_buf_size = response_buf_size;

        /*
        long long current_time = timeInMilliseconds();
        while (timeInMilliseconds() - current_time < 100) { // recv continuously within 100ms
          if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) {
            fprintf(stderr, "break;\n");
            break;
          }
        }
        */

        if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) { 
          //break;
          fprintf(stderr, "recv error\n");
          return 1;
        }


        fprintf(stderr, "**********************************************************\n");
        if (response_buf_size > old_response_buf_size) {
          fprintf(stderr, "received: %s\n", response_buf+old_response_buf_size);
          int n_return_codes = 0;
          unsigned int *my_state_sequence;
          my_state_sequence = (*extract_response_codes)(response_buf+old_response_buf_size, response_buf_size-old_response_buf_size, &n_return_codes);
          // my_state_sequence[1] = current response code
          fprintf(stderr, "Return codes: ");
          for (int h = 0; h < n_return_codes; h++) {
            fprintf(stderr,"%d-",my_state_sequence[h]);
          }

          if (strncmp("HELP", buf, strlen("HELP")) == 0) {
              fprintf(stderr, "HELP detected, skipping\n");
          }
          else {
            fprintf(stderr, "**(n_cmds, n_return_codes) [n_return_codes is always 1/2 more, at pos 0 is always 0.]: (%d,%d)\n", n_cmds, n_return_codes);
            if (n_return_codes-1 != 1 && n_return_codes-1 != 2) {
              fprintf(stderr, "mismatch. we should always get 1, sometimes 2 return codes. \n");
              return 1;
            }
            /*
            if (strncmp("LIST", buf, strlen("LIST")) == 0) {
                fprintf(stderr, "LIST detected, expecting 2 return codes, e.g. 150/226\n");
                if (2 != n_return_codes-1) {// technically should always send only 1//(n_cmds != n_return_codes-1) {
                  fprintf(stderr, "mismatch\n");
                  return 2;
                }
            }
            else {
              // normal case
              if (1 != n_return_codes-1) {// technically should always send only 1//(n_cmds != n_return_codes-1) {
                fprintf(stderr, "mismatch\n");
                return 1;
              }
            }
            */
          }
          fprintf(stderr, "--------------------------------------------------------\n\n");


          // CSV logging code
          // cmd_prefix will be handled in Python to link this with to the appropriate protocol command.
          unsigned int BUF_SIZE = 1024;
          char *cmd_prefix = malloc(BUF_SIZE);
          memset(cmd_prefix, 0, BUF_SIZE);
          unsigned int dump_length = min(region_size, 100); // 100 is large enough even for rtsp, openssh etc.
          for (int j=0; j < dump_length; j++) { 
            char middle_str[] = "%.2x:";
            char end_str[] = "%.2x";
            char* format_str;
            if (j == dump_length-1) {
              format_str = end_str;
            }
            else {
              format_str = middle_str;
            }
            cmd_prefix += sprintf(cmd_prefix, format_str, buf[regions[i].start_byte + j] & 0xff);
          }


          // There can be 1 or 2 response codes. I think not more than that. In the csv, they're joined with ":".
          char* response_codes = malloc(BUF_SIZE);
          memset(response_codes, 0, BUF_SIZE);
          // n_return_codes[0] is some dummy element and always 0.
          for (int h = 1; h < n_return_codes; h++) {
            char middle_str[] = "%d:";
            char end_str[] = "%d";
            char* format_str;
            if (h == n_return_codes-1) {
              format_str = end_str;
            }
            else {
              format_str = middle_str;
            }
            response_codes += sprintf(response_codes, format_str, my_state_sequence[h]);
          }

          unsigned int timestamp = get_timestamp(argv[2]);
          pairlog(pair_output_dir, timestamp, cmd_prefix, response_codes);

          free(response_codes);
          free(cmd_prefix);

          offsets_responses[responses++] = old_response_buf_size;
          old_response_buf_size = response_buf_size;
        }
        else {
          no_responses++;
          fprintf(stderr, "no response\n");
          return 25;
        }
      }
    }
  }

  fclose(fp);
  close(sockfd);

  //Extract response codes
  state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  fprintf(stderr,"\n--------------------------------");
  fprintf(stderr,"\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr,"%d-",state_sequence[i]);
  }

  fprintf(stderr,"\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
  for (i=0; i < response_buf_size; i++) {
    fprintf(stderr,"%c",response_buf[i]);
  }
  fprintf(stderr,"\n--------------------------------");

  //Free memory
  ck_free(state_sequence);
  if (buf) ck_free(buf);
  ck_free(response_buf);

  return 0;
}

