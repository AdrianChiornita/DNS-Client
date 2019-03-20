#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUFLEN 256
#define MAX_DNS_SERVERS 20
#define LENMSG 512
#define MAXRECORDS 30

/** Configation File :: IP addresses of DNS servers **/
#define DNS_SERVERS "dns_servers.conf"

/** File for previous queries **/
#define QUERY_LOG "message.log"

/** File for previous records **/
#define RECORD_LOG "dns.log"


/*** -- Query & Resource Record Type: -- ***/
#define A       1   //  IPv4 address
#define NS      2   //  Authoritative name server
#define CNAME   5   //  Canonical name for an alias
#define MX      15  //  Mail exchange
#define SOA     6   //  Start Of a zone of Authority
#define TXT     16  //  Text strings

/*** -- Define DNS message format -- ***/

/** Header section format **/
/**
                                 1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

typedef struct {
    unsigned short id;          // Identification Number
    unsigned char rd :1;        // Recursion Desired
    unsigned char tc :1;        // Truncated Message
    unsigned char aa :1;        // Authoritive Answer
    unsigned char opcode :4;    // Purpose of Message
    unsigned char qr :1;        // Query/Response flag: 0 = query
                                //                      1 = response
    unsigned char rcode :4;
    unsigned char z :3;
    unsigned char ra :1;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} dns_header_t;


/** Question section format **/
/**
                                 1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

typedef struct {
    // qname variabil
    unsigned short qtype;
    unsigned short qclass;
} dns_question_t;

/** Resource record format **/
/**
                                 1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

typedef struct {
    // name dynamic
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
    // rdata dynamic
} dns_rr_t;

/** replace for bool from C++ **/
enum boolean {
    false,
    true
};

unsigned char buffer[LENMSG];
unsigned char dns_servers[MAX_DNS_SERVERS][BUFLEN];
unsigned int  number_dns;
unsigned int  current_server;

unsigned char  hostname[BUFLEN];
unsigned short query_type;
FILE *query_log;
FILE *record_log;

void read_conf_file();
unsigned short choose_type(char *);

unsigned int create_message_query();
unsigned char* find_name(unsigned char*, unsigned int*);
void check_response(unsigned int);

int main( int argc, char *argv[]) {

    if (argc < 3) {
		printf("[ERROR] :: Usage client: %s <domain_name>/<ip_address> <query_type>\n", argv[0]);
		exit(-1);
	}
    strcpy((char *) hostname, argv[1]);
    query_type = choose_type(argv[2]);

    if (query_type == 0) {
        printf("[ERROR] :: The query type %s is not implemented.\n", argv[2]);
		exit(-1);
    }

    if ((query_log = fopen(QUERY_LOG , "a")) == NULL) {
         printf("[ERROR] :: Failed opening %s file.\n", QUERY_LOG);
         exit(-1);
    }

    if ((record_log = fopen(RECORD_LOG , "a")) == NULL) {
         printf("[ERROR] :: Failed opening %s file.\n", RECORD_LOG);
         exit(-1);
    }

    read_conf_file();

    int sock;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("[ERROR] :: Cannot create UDP socket.\n");
		exit(-1);
    }

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons( 53 );
    inet_aton((char *) dns_servers[current_server], &serv_addr.sin_addr);

    unsigned int length = create_message_query();
    socklen_t size = sizeof(struct sockaddr);

    if (sendto(sock, (char *) buffer, length, 0, (struct sockaddr *) &serv_addr, size) < 0) {
        printf("[ERROR] :: Cannot send message to DNS server.\n");
        exit(-1);
    }

    memset(buffer, 0, LENMSG);
    unsigned int recvlen;

    if ((recvlen = recvfrom(sock, (char *) buffer, LENMSG, 0, (struct sockaddr *) &serv_addr, &size)) < 0) {
        printf("[ERROR] :: Cannot receive message from DNS server.\n");
        exit(-1);
    }

    check_response(length);

    if (close(sock) < 0) {
        printf("[ERROR] :: Cannot close UDP socket.\n");
		exit(-1);
    }

    return 0;
}

void check_response (unsigned int size) {

    dns_header_t* header = (dns_header_t *) &buffer;
    unsigned char* rec = &buffer[size];

    unsigned int counter = 0;
    for (int i = 0; i < ntohs ( header -> ancount ); ++i) {

        unsigned char* rname = find_name(rec, &counter);

        rec += counter;
        fprintf(record_log, "%s ", rname);

        dns_rr_t* resource = (dns_rr_t *) rec;
        rec += sizeof(dns_rr_t);
        fprintf(record_log, "%d %d ", ntohs( resource -> class ), ntohs( resource -> type ));

       fprintf(record_log, "\n");
    }
}

unsigned char* find_name(unsigned char* pointer, unsigned int* forward) {
    *forward = 1;

    unsigned char *name = (unsigned char *) malloc(BUFLEN);
    name[0] = '\0';

    unsigned int point = false;
    unsigned int k = 0;
    while (*pointer != 0) {

        if ( *pointer < 192) {
            name[k++] = *pointer;
        } else {
            unsigned int offset = (*pointer) * 256 +
                                  *(pointer + 1) -
                                  49152;
            pointer = &buffer[offset - 1];
            point = true;
        }
        if (!point) *forward = *forward + 1;
        pointer++;
    }
    name[k] = '\0';
    if (point) *forward = *forward + 1;

    unsigned int l = strlen((char *) name);
    for (int i = 0; i < l; ++i) {
        int dot = name[i];
        for (int j = 0; j < dot; ++j) {
            name[i]  = name[i + 1];
            i++;
        }
        name[i] = '.';
    }
    name[l - 1] = '\0';

    return name;
}

unsigned int create_message_query () {
    unsigned int size = 0;
    memset(buffer, 0, LENMSG);

    dns_header_t* header =  (dns_header_t *) &buffer;
    header -> id      = (unsigned short) htons( getpid() );
    header -> rd      = 1;
    header -> tc      = 0;
    header -> aa      = 0;
    header -> opcode  = 0;
    header -> qr      = 0;
    header -> rcode   = 0;
    header -> z       = 0;
    header -> ra      = 0;
    header -> qdcount = (unsigned short) htons( 1 );
    header -> ancount = 0;
    header -> nscount = 0;
    header -> arcount = 0;

    size += sizeof(dns_header_t);

    unsigned char* qname = (unsigned char*) &buffer[sizeof(dns_header_t)];
    strcat((char *) hostname, ".");
    unsigned int length     = strlen((char *) hostname);
    unsigned char* iterator = qname;
    unsigned int last       = 0;

    iterator++;
    for (int i = 0; i < length; ++i) {

        if (hostname[i] != '.') *iterator++ = hostname[i];
        else {
            *iterator++ = hostname[i];
            qname[last] = i - last;
            last = i + 1;
        }
    }

    --iterator;
    *iterator = '\0';
    size += strlen((char *) qname) + 1;


    dns_question_t* question = (dns_question_t *)
            &buffer[sizeof(dns_header_t) + strlen((char *) qname) + 1];
    question -> qtype  = htons ( query_type );
    question -> qclass = htons ( 1 );

    size += sizeof(dns_question_t);

    for(int i = 0; i < size; i++){
        fprintf(query_log,"%.2x ", buffer[i]);
    }
    fprintf(query_log,"\n");

    return size;
}

unsigned short choose_type(char *argument) {
    if (strcmp(argument, "A") == 0) return A;
    if (strcmp(argument, "NS") == 0) return NS;
    if (strcmp(argument, "CNAME") == 0) return CNAME;
    if (strcmp(argument, "MX") == 0) return MX;
    if (strcmp(argument, "SOA") == 0) return SOA;
    if (strcmp(argument, "TXT") == 0) return TXT;
    return 0;
}

void read_conf_file () {
    FILE *dns_servers_file;
    char buffer[BUFLEN];

    if ((dns_servers_file = fopen(DNS_SERVERS , "r")) == NULL) {
         printf("[ERROR] :: Failed opening %s file.\n", DNS_SERVERS);
         exit(-1);
    }

    while (fgets(buffer, BUFLEN, dns_servers_file) != NULL) {
        if(buffer[0] == '#') continue;

        char *token;
        char delimiters[3] = " \n";

        token = strtok(buffer, delimiters);
        strcpy((char *) dns_servers[number_dns] , token);
        number_dns++;
    }

    if (fclose(dns_servers_file) == EOF) {
        printf("[ERROR] :: Failed closing %s file.\n", DNS_SERVERS);
        exit(-1);
    }
}
