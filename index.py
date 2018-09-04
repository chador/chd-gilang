From: <Saved by Blink>
Subject: 
Date: Wed, 4 Sep 2018 07:32:54 -0000
MIME-Version: 1.0
Content-Type: multipart/related;
	type="text/html";
	boundary="----MultipartBoundary--fM5v4o5hmMBPxhbnNPxFT7r0X6F3C1r0GqKsGRv9w0----"

------MultipartBoundary--fM5v4o5hmMBPxhbnNPxFT7r0X6F3C1r0GqKsGRv9w0----
Content-Type: text/html
Content-ID: <frame-6-92cf23ea-3eca-43b2-8644-0f1670103268@mhtml.blink>
Content-Transfer-Encoding: quoted-printable
Content-Location: https://dl.packetstormsecurity.net/UNIX/scanners/netscan.c

<html><head><meta http-equiv=3D"Content-Type" content=3D"text/html; charset=
=3DUTF-8"></head><body><div style=3D"background: #d8ffd8;font-size:45px; wo=
rd-wrap: break-word; white-space: pre-wrap;">/*
	gcc -lpthread netscan.c -o netscan
	Tcp/Udp/Tor port scanner with: synpacket, connect TCP/UDP and socks5(tor c=
onnection)=20
*/=20

#include &lt;math.h&gt;
#include &lt;time.h&gt;
#include &lt;stdio.h&gt;
#include &lt;errno.h&gt;
#include &lt;netdb.h&gt;
#include &lt;fcntl.h&gt;
#include &lt;ctype.h&gt;
#include &lt;getopt.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;string.h&gt;
#include &lt;unistd.h&gt;
#include &lt;signal.h&gt;
#include &lt;net/if.h&gt;
#include &lt;pthread.h&gt;
#include &lt;termios.h&gt;
#include &lt;sys/mman.h&gt;
#include &lt;sys/time.h&gt;
#include &lt;sys/wait.h&gt;
#include &lt;sys/ioctl.h&gt;
#include &lt;sys/types.h&gt;
#include &lt;sys/socket.h&gt;
#include &lt;arpa/inet.h&gt;

#include &lt;netinet/in.h&gt;
#include &lt;netinet/ip.h&gt;
#include &lt;netinet/tcp.h&gt;
#include &lt;netinet/udp.h&gt;
#include &lt;netinet/ip_icmp.h&gt;
#include &lt;netinet/in_systm.h&gt;

#define LPORT       1
#define HPORT       65535    =20
#define TCPSZ		sizeof(struct iphdr)+sizeof(struct tcphdr)
#define PSESZ       sizeof(struct pseudohdr)+sizeof(struct tcphdr)
#define TORPORT     9050
#define TORCTRL     9051
#define LOCALHOST   "127.0.0.1"
#define SOCKS5      "\x05\x01\x00"
#define UDP_RESEND  6
#define UDP_PACKET  4096

/* global var */
static int verbose;
static int syn;
static int conn;
static int tor;
static int normal;
static int progress;
static int rangeport;
static int singleport;
static int specificport;
static int udp;
static int webserver;
static int banserv;

unsigned int delay=3D50000, timeout=3D1, timeout_s=3D1, timeout_u=3D200;
unsigned short min, max, port;
unsigned short index_p=3D0, index_o=3D0, index_c=3D0, index_f=3D0;
unsigned short ports[HPORT], open_p[HPORT], closed_p[HPORT], filtred_p[HPOR=
T];
char *hostname, *eth0, *ipsource;

typedef enum { false, true } bool;

/* struct tcp syn packet */
struct pseudohdr  {
	in_addr_t src;
    in_addr_t dst;
    char padd;
    char proto;
    unsigned short len;
};

/* struct progress bar */
typedef struct {
    char start;
    char end;
    char block;
    char cursor;
    unsigned int width;
    double max;
    bool percent;
    bool update;
} bar;

/* setup char for progress bar */
void setupbar(bar * set) {
    set-&gt;start   =3D '[';
    set-&gt;end     =3D ']';
    set-&gt;block   =3D '=3D';
    set-&gt;cursor  =3D '&gt;';
    set-&gt;percent =3D true;
    set-&gt;update  =3D false;
    set-&gt;max     =3D 100;
    set-&gt;width   =3D 40;
}

/* Progress bar */
void progressbar(double pos, bar * set) {
    unsigned int print =3D (unsigned int)(set-&gt;width*pos/set-&gt;max);
    unsigned count;
    if(set-&gt;update) {
        for(count=3Dset-&gt;width+2+(set-&gt;percent?5:0); count; count--)
            putchar('\b');
    } else set-&gt;update =3D true;       =20
    putchar(set-&gt;start);
    count =3D set-&gt;width;
    for(; print&gt;1; print--, count--)
        putchar(set-&gt;block);
    putchar((set-&gt;max =3D=3D pos) ? set-&gt;block : set-&gt;cursor);
    count--;
    for(; count; count--)
        putchar(' ');
    putchar(set-&gt;end);
    if(set-&gt;percent)
        printf(" %3d%%", (int)(100*pos/set-&gt;max));
    fflush(stdout);
}

void help() {
  //printf("[*] Network Scanner v1.0 helper %s %s\n",__TIME__, __DATE__);
	printf("  -c | --connect\tTcp protocol\n");
	printf("  -s | --syn\t\tSyn packet scanner\n");
	printf("  -t | --tor\t\tTor scanner default 127.0.0.1:9050\n");
	printf("  -u | --udp\t\tUdp protocol\n");
	printf("  -b | --banner\t\tParse service banner\n");
	printf("  -p | --port\t\tPort method A, A-B, A,B,C,D\n");
	printf("  -d | --delay\t\tDelay synpack in ms [min: 50000]\n");
	printf("  -v | --verbose\tVerbose output\n");
	printf("  -h | --help\t\tPrint help menu\n\n");
	printf("  Example: scan -s google.it\n");
	printf("           scan -c google.it\n");
	printf("           scan -t google.it\n");
	printf("           scan -c -b google.it\n");
	printf("           scan -c -p1-100 google.it\n");
	printf("           scan -c -p1,2,3,4 google.it\n");
	exit(0);
} =20
=20
void ctrlc(int sig) {
	printf("\n\n    CTRL+C intercepted exit scanner\n");
	exit(0);
}

/* error control on port value */
int portcontrol(char *arg) {
	if(strstr(arg,"-") !=3D NULL) {
		rangeport =3D 1;
		sscanf(arg, "%hu%*c%hu", &amp;min,&amp;max);
		if(min &gt;=3D max || min &gt; HPORT-1 || max &gt; HPORT || max =3D=3D LP=
ORT) {
			printf("    [RANGE-ERROR] invalid port range %s\n\n", arg);
			exit(0);
		}
		return 0;
	}
	if(strstr(arg,",") !=3D NULL) {
		specificport =3D 1;
		char *p;
		p =3D strtok(arg, ",");
		while(p !=3D NULL) {
			ports[index_p++] =3D (unsigned short)atoi(p);
			p =3D strtok(NULL, ",");
		}
		return 0;
	}=20
	singleport =3D 1;
	min =3D atoi(arg);
	return 0;
}

int service() {
	struct servent *se;
	int i=3D0;
	if(!udp) {
		while((se =3D getservent())) {
			if(strcmp(se-&gt;s_proto, "tcp") =3D=3D 0)
				i++;
		} return i;
	}
	if(udp) {
		while((se =3D getservent())) {
			if(strcmp(se-&gt;s_proto, "tcp") =3D=3D 0)
				i++;
		} return i;=09
	} return -1;
}

char* resolveHost (char *host)  {=20
	struct hostent *he;
	struct in_addr a; =20
    if((he =3D gethostbyname(host))) {
        while (*he-&gt;h_addr_list) {
            bcopy(*he-&gt;h_addr_list++, (char *) &amp;a, sizeof(a));
            return inet_ntoa(a);
        }
    }
	return 0;
}

int cmpfunc(const void *a, const void *b) {
    return (*(unsigned short*)a - *(unsigned short*)b);
}

/* remove duplicate */
unsigned short* rmdup(unsigned short *v, int size) {
    int i,index=3D0;
    unsigned short *new_v =3D (unsigned short*)malloc(size*sizeof(unsigned =
short));
    if (size =3D=3D 1)
		new_v[0] =3D v[0];
    else {
		for (i=3D1; i&lt;size; i++) {
			if (v[i] !=3D v[i-1])=20
				new_v[index++] =3D v[i-1];
        }
    }
    return new_v;
}

/* get banner service on open port */
char *bannerservice(unsigned short bport) {
	int sock, conn, ctra, ctrb, sendbytes, rcvdbytes;
	char banner[1000], *httpdsptr, *httpdbptr, ip_addr[16];
	struct sockaddr_in ban;
	struct hostent *host;
	struct timeval tm;=09
	tm.tv_sec =3D 1;
	tm.tv_usec =3D 0;
	host =3D gethostbyname(hostname);
	bzero(banner,1000);
	strcpy(ip_addr, (char *)inet_ntoa(*((struct in_addr *)host-&gt;h_addr)));
	if((sock =3D socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) =3D=3D -1)
		return ("N.B. error");
	if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&amp;tm, sizeof(struc=
t timeval)) =3D=3D -1)=20
		return ("N.B. error");
	ban.sin_family=3DAF_INET;
	ban.sin_port=3Dhtons(bport);
	ban.sin_addr.s_addr=3Dinet_addr(hostname);
	if((conn =3D connect(sock,(struct sockaddr *)&amp;ban, sizeof(struct socka=
ddr))) =3D=3D -1)=20
		return ("N.B. error");
	if(bport =3D=3D 80)=20
		sendbytes =3D send(sock, "HEAD / HTTP/1.0\n\n", 19, 0);
	rcvdbytes =3D recv(sock, banner, 1000, 0);
	if(bport =3D=3D 80)  {
		httpdsptr =3D strstr(banner,"Server");
		for(ctra=3D0; ctra!=3Dstrlen(httpdsptr); ctra++) {
			if(httpdsptr[ctra] =3D=3D '\n') {=20
				httpdsptr[ctra] =3D '\0';=20
				break;=20
			}=20
		}
		httpdbptr =3D (char *)malloc(ctra-8);
		for(ctrb=3D0; ctrb!=3Dctra; ctrb++) {
			httpdbptr[ctrb] =3D httpdsptr[ctrb+8];
			if(httpdsptr[ctrb+8] =3D=3D '\0') {=20
				break;=20
			}=20
		}
	=09
		printf("[");=20
		if(strlen(httpdbptr) &gt; 0) {
			httpdbptr[strcspn(httpdbptr,"\r")] =3D '\0';
			printf("%s", httpdbptr);
		} else printf("N.d");
		printf("]");
		fflush(stdout);
	} else  {
		printf("[");
		if(strlen(banner) &gt; 0) {
			banner[strcspn(banner,"\r")] =3D '\0';
			printf("%s", banner);
		} else printf("N.d.");
		printf("]");=20
		fflush(stdout);
	}
	close(sock);
	return 0;
}

/* statistics port status */
int statistic() {
	struct servent *se;
	unsigned short *new_o,i,total;
	new_o =3D rmdup(open_p, index_o+1);
	for(i=3D0; i&lt;index_o; i++);
	total=3Di;
	qsort(new_o, total, sizeof(unsigned short), cmpfunc);
	if(verbose)
		    printf("     ****** STATISTICS ******\n\n");
	for(i=3D0; i&lt;total; i++) {
		if(new_o[i] =3D=3D 80)
			webserver =3D 1;
		if(verbose &amp;&amp; !udp)
			printf("     OPEN\t%d", new_o[i]);
		if(verbose &amp;&amp; udp)
			printf("     OPEN|filtred\t%d", new_o[i]);
		if(!verbose)
			printf("     OPEN\t%d", new_o[i]);
		if(!udp) {
			if((se =3D getservbyport(htons(new_o[i]), "tcp")))
				printf("\t%s ", se-&gt;s_name);
			else printf("\tunknown ");
		}
		if(udp) {
			if((se =3D getservbyport(htons(new_o[i]), "udp")))
				printf("\t%s\n", se-&gt;s_name);
			else printf("\tunknown\n");
		}=20
		if(banserv || (!banserv &amp;&amp; new_o[i] =3D=3D 80)) {
			putchar('\t');
			bannerservice(new_o[i]);
		}
		putchar('\n');
	}
	if(webserver &amp;&amp; !banserv) {
		printf("\n[*] Webserver detected: ");
		bannerservice(80);
	}
	if(syn) {
		index_o =3D i;
		if(normal)
			index_f =3D 312-index_o-index_c;
		if(rangeport) {
		    index_f =3D (max-min+1)-index_o-index_c;
		}
	}
	if(index_o =3D=3D 0)
		printf("\n[*] ALL ports are closed.");
	printf("\n[*] Statistics: open %d closed %d filtred %d, ", index_o, index_=
c, index_f);=09
	return 0;
}

/* get last up interface (good if you use vpn) */
int interface() {
	char  buf[8192],ip[INET6_ADDRSTRLEN];
	struct ifconf   ifc; //=3D {0};
	struct ifreq   *ifr =3D NULL;
	int sck=3D0,nif=3D0,i=3D0;
	struct ifreq    *item;
	struct sockaddr *addr;
	sck =3D socket(PF_INET, SOCK_DGRAM, 0);
	if(sck &lt; 0) {
		perror("[ERROR] socket() interface: ");
		exit(0);
	}
	ifc.ifc_len =3D sizeof(buf);
	ifc.ifc_buf =3D buf;
	if(ioctl(sck, SIOCGIFCONF, &amp;ifc) &lt; 0) {
		perror("[ERROR] ioctl(SIOCGIFCONF): ");
		exit(0);
	}
	ifr =3D ifc.ifc_req;
	nif =3D ifc.ifc_len/sizeof(struct ifreq);=20
	for(i =3D 0; i &lt; nif; i++) {
		item =3D &amp;ifr[i];
		addr =3D &amp;(item-&gt;ifr_addr);
	}
	eth0 =3D item-&gt;ifr_name;
	ipsource =3D (char*)inet_ntop(AF_INET,&amp;(((struct sockaddr_in *)addr)-&=
gt;sin_addr),ip, INET6_ADDRSTRLEN);
	return 0;
}

unsigned short checksum (unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum =3D 0; nwords &gt; 0; nwords--)
        sum +=3D *buf++;
    sum =3D (sum &gt;&gt; 16) + (sum &amp; 0xffff);
    sum +=3D (sum &gt;&gt; 16);
    return ~sum;
}

/* check private ip (nmap function)*/
int checkip(char *ip) {
	unsigned int i1[4];
	sscanf(ip,"%3u.%3u.%3u.%3u", &amp;i1[0], &amp;i1[1], &amp;i1[2], &amp;i1[3=
]);
	if (i1[0] &gt;=3D 224)
		return 1;
	if (i1[0] &gt;=3D 96 &amp;&amp; i1[0] &lt;=3D 127)
		return 1;
	if (i1[0] &gt;=3D 70 &amp;&amp; i1[0] &lt;=3D 79)
		return 1;
	if (i1[0] &gt;=3D 83 &amp;&amp; i1[0] &lt;=3D 95)
		return 1;		=09
	if (i1[0] =3D=3D 172 &amp;&amp; i1[1] &gt;=3D 16 &amp;&amp; i1[1] &lt;=3D =
31)
		return 1;
	if (i1[0] =3D=3D 192) {
		if (i1[1] =3D=3D 168)
			return 1;
		else if (i1[1] =3D=3D 0 &amp;&amp; i1[2] =3D=3D 2)
			return 1;
	}
	if (i1[0] =3D=3D 169 &amp;&amp; i1[1] =3D=3D 254)
		return 1;
	if (i1[0] =3D=3D 204 &amp;&amp; i1[1] =3D=3D 152 &amp;&amp; (i1[2] =3D=3D =
64 || i1[2] =3D=3D 65))
		return 1;
	if (i1[0] =3D=3D 255 &amp;&amp; i1[2] =3D=3D 255 &amp;&amp; i1[3] =3D=3D 2=
55)
		return 1;
	return 0;
}

void synpacket(int sockfd, struct sockaddr_in sinaddr) {
	struct iphdr ip;
    struct tcphdr tcp;
    struct pseudohdr pseudo;
    int attrib;
    char *buff =3D (char*)malloc(TCPSZ);
    char tmp[sizeof(struct pseudohdr)+sizeof(struct tcphdr)];
    memset(&amp;ip, 0x0, sizeof(struct iphdr));
    memset(&amp;tcp, 0x0, sizeof(struct tcphdr));
    ip.version              =3D 4;
    ip.ihl                  =3D 5;
    ip.tot_len              =3D TCPSZ;
    ip.id                   =3D htonl(12345);
    ip.ttl                  =3D 255;
    ip.protocol             =3D IPPROTO_TCP;
    ip.saddr                =3D inet_addr(ipsource);
    ip.daddr                =3D inet_addr(hostname);
    ip.check                =3D checksum((unsigned short*) &amp;ip, ip.tot_=
len &gt;&gt; 1);
    tcp.source              =3D (rand()%64511)+1024;
    tcp.dest                =3D htons(port);
    tcp.seq                 =3D (rand()%0xFFFFFFFF);
    tcp.ack_seq             =3D 0;
    tcp.doff                =3D 5;
    tcp.syn                 =3D 1;
    tcp.window              =3D htonl(0xffff);
    tcp.check               =3D 0;
    sinaddr.sin_family      =3D AF_INET;
    sinaddr.sin_port        =3D htons(port);
    sinaddr.sin_addr.s_addr =3D inet_addr(hostname);
    attrib                  =3D 1;
    memset(tmp, 0x0, sizeof(struct pseudohdr)+sizeof(struct tcphdr));
    memset(buff, 0x0, TCPSZ);
    pseudo.src   =3D ip.saddr;
    pseudo.dst   =3D ip.daddr;
    pseudo.padd  =3D 0;
    pseudo.proto =3D ip.protocol;
    pseudo.len   =3D htons(sizeof(struct tcphdr));
    memcpy(tmp, &amp;pseudo, sizeof(struct pseudohdr));
    memcpy(tmp+sizeof(struct pseudohdr), &amp;tcp, sizeof(struct tcphdr));
    tcp.check =3D checksum ((ushort*) tmp, (PSESZ) &gt;&gt; 1);
    memcpy(buff, &amp;ip, sizeof(struct iphdr));
    memcpy(buff+sizeof(struct iphdr), &amp;tcp, sizeof(struct tcphdr));
    if (sendto (sockfd, buff, ip.tot_len, 0, (struct sockaddr *) &amp;sinad=
dr, sizeof (sinaddr)) &lt; 0)  {
		fprintf (stderr,"*** Error in sendto: %s\n",strerror(errno));
        exit(1);
    }
    usleep(delay);
}

void* ackSniffer(void *arg)  {
    int sockfd;
    size_t sin_size=3Dsizeof(struct sockaddr);
    struct iphdr ip;
    struct tcphdr tcp;
    struct sockaddr_in sock;
    char pack[HPORT];
   =20
    if((sockfd=3Dsocket (PF_INET, SOCK_RAW, IPPROTO_TCP))&lt;0) {
        fprintf (stderr,"*** Fatal - Unable to create a raw socket: %s\n",s=
trerror(errno));
		exit(-1);
    }
    sock.sin_family=3DAF_INET;
    sock.sin_port=3D0;
    sock.sin_addr.s_addr=3Dinet_addr(hostname);
    while(1) {
		memset (&amp;ip,0x0,sizeof(struct iphdr));
        memset (&amp;tcp,0x0,sizeof(struct tcphdr));
        if(recvfrom(sockfd, pack, sizeof(pack), 0, (struct sockaddr*) &amp;=
sock, &amp;sin_size)&lt;0) {
			fprintf (stderr,"*** Fatal - Error in recvfrom(): %s\n",strerror(errno))=
;
            exit(-2);
        }
        memcpy (&amp;ip,pack,sizeof(struct iphdr));
        memcpy (&amp;tcp,pack+sizeof(struct iphdr),sizeof(struct tcphdr));
        if (ip.saddr =3D=3D inet_addr(hostname) &amp;&amp; tcp.ack &amp;&am=
p; !tcp.rst &amp;&amp; ntohs(tcp.source)){//&gt;=3D min &amp;&amp; ntohs(tc=
p.source) &lt;=3D max) {
			if(verbose) {
				printf ("    [OPEN] ACK sniffed %s:%u\t [winsize %d] [ttl %d]\n",hostna=
me,ntohs(tcp.source),tcp.window,ip.ttl);
				fflush(stdout);
			}
            open_p[index_o++] =3D ntohs(tcp.source);
		} else if (ip.saddr =3D=3D inet_addr(hostname) &amp;&amp; tcp.ack &amp;&a=
mp; tcp.rst) {
			closed_p[index_c++] =3D ntohs(tcp.source);
        }
	}
    pthread_exit(0);
}

int setupsock(struct sockaddr_in sock) {
	struct timeval tm;
	int sd, attrib =3D 1;
	if(syn) {
		pthread_t t;
		if(pthread_create (&amp;t,NULL,ackSniffer,NULL)) {
			fprintf (stderr," [ERROR-ACKSNIFFER] Thread process create: [%s]\n",stre=
rror(errno));
			exit(0);
		}		=09
		if((sd =3D socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) &lt; 0) {
			fprintf(stderr, " [SYN - SOCKET] Unable to create raw socket: [%s]", str=
error(errno));
			exit(0);
		}	=09
		if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &amp;attrib, sizeof(attrib)) &l=
t; 0)  {
			fprintf(stderr, " [SYN - SOCKOPT] Error in setsockopt: [%s]\n",strerror(=
errno));
			exit(0);
		}  =20
	}
	if(conn || tor) {
		tm.tv_sec =3D timeout;
		tm.tv_usec =3D 0;
		sock.sin_family =3D AF_INET;
		if(conn) {
			sock.sin_port =3D htons(port);
			sock.sin_addr.s_addr =3D inet_addr(hostname);
		}
		if(tor) {
			sock.sin_port =3D htons(TORPORT);
			sock.sin_addr.s_addr =3D inet_addr(LOCALHOST);
		}
		if((sd =3D socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) &lt; 0) {
			fprintf(stderr, " [CONNECT - ERROR] Unable to create socket: [%s]", stre=
rror(errno));
			exit(0);
		}
		if(conn) {
            fd_set fdset;
            fcntl(sd, F_SETFL, O_NONBLOCK);
            connect(sd, (struct sockaddr *)&amp;sock, sizeof(sock));
            FD_ZERO(&amp;fdset);
            FD_SET(sd, &amp;fdset);
            if(select(sd+1, NULL, &amp;fdset, NULL, &amp;tm) =3D=3D 1) {
                int so_error;
                socklen_t len =3D sizeof(so_error);
                getsockopt(sd, SOL_SOCKET, SO_ERROR, &amp;so_error, &amp;le=
n);
                if(so_error =3D=3D 0) {
					if(verbose)
						printf("      OPEN\t\t%d\n", port);
                    open_p[index_o++] =3D port;
                } else {
					if(verbose)
						printf("      CLOSED\t\t%d\n", port);
                    closed_p[index_c++] =3D port;
                }
            } else {
				if(verbose)
					printf("      FILTRED\t\t%d\n", port);
                filtred_p[index_f++] =3D port;
            }
            close(sd);
            return 0;
        }
        if(tor) {
			if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &amp;attrib, 4) &lt; 0)  {
				fprintf(stderr," [TOR - SETSOCKOPT] SO_REUSEADDR: [%s]\n",strerror(errn=
o));
				exit(0);
			}
			if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&amp;tm, sizeof(struct=
 timeval)) &lt; 0)  {
				fprintf (stderr," [TOR - SETSOCKOPT] SO_RCVTIMEO: [%s]\n",strerror(errn=
o));
				exit(0);
			}
			if(connect(sd, (struct sockaddr*)&amp;sock, sizeof(sock)) !=3D 0) {
				fprintf(stderr," [TOR - CONNECT] Connect 127.0.0.1:9050: [%s]\n",strerr=
or(errno));
				exit(0);
			}=09
		}		=20
	}
	return sd;
}

void udpscan(unsigned short port) {
	struct sockaddr_in myudp; =20
	char buff[] =3D "0x0x0x0x0x0x0x0x0x0";

	int udpsock, rawsock, retry, retval, iplen;
	fd_set r;
	struct timeval mytimeout;
	struct icmp *packet;
	struct ip *iphdr;
	unsigned char recvbuff[UDP_PACKET];

	if((udpsock =3D socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) &lt; 0) {
		perror("  [ERROR] Udp Socket: ");
		exit(-1);
    }
	if((rawsock =3D socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) &lt; 0) {
		perror("  [ERROR] Icmp raw_sock: ");
		exit(-1);
    }
	mytimeout.tv_sec =3D 2;
	mytimeout.tv_usec =3D 0;
	myudp.sin_family =3D AF_INET;
	myudp.sin_port =3D htons(port);
	myudp.sin_addr.s_addr =3D inet_addr(hostname);=09
	retry =3D 0;
	while(retry++ &lt; UDP_RESEND) {
		if((sendto(udpsock,buff,sizeof(buff),0x0,(struct sockaddr *)&amp;myudp,si=
zeof(myudp))) &lt; 0) {
			perror("  [ERROR] Udp Sendto: ");
			exit(-1);
		}
		FD_ZERO(&amp;r);
		FD_SET(rawsock,&amp;r);
		retval =3D select((rawsock+1),&amp;r,NULL,NULL,&amp;mytimeout);=20
		if(retval) {
			if((recvfrom(rawsock,&amp;recvbuff,sizeof(recvbuff),0x0,NULL,NULL)) &lt;=
 0) {
				perror("  [ERROR] Udp Recv: ");
				exit(-1);
			}
			iphdr =3D (struct ip *)recvbuff;
			iplen =3D iphdr-&gt;ip_hl &lt;&lt; 2;
			packet =3D (struct icmp *)(recvbuff + iplen);
			if((packet-&gt;icmp_type =3D=3D ICMP_UNREACH) &amp;&amp; (packet-&gt;icm=
p_code =3D=3D ICMP_UNREACH_PORT))
				break;
		} else continue;
	}
	if(retry &gt;=3D UDP_RESEND) {
		open_p[index_o++] =3D port;
		if(verbose) {
			printf("      OPEN|filtred\t%d\n", port);
			fflush(stdout);
		}
	} else closed_p[index_c++] =3D port;
}

int torscan() {
	struct sockaddr_in torsocks;
	struct servent *service;
	unsigned short portserv;
	char *buf =3D calloc(1024, sizeof(char));
    short l =3D strlen(hostname);
    short t;
    int x,sockt;
   =20
    if(checkip(hostname)) {
		printf("    [TOR-SOCKS5] Reject connection to private address\n");
		exit(0);
    }
    sockt =3D setupsock(torsocks);
    write(sockt, SOCKS5, 3);=20
    read(sockt, buf, 1024);
    if((buf[0] !=3D 0x05) || (buf[1] =3D=3D 0xFF) || (buf[1] !=3D 0x00)) {
		printf("Socks5 error!\n");
        exit(0);
	}
    buf[0] =3D 0x05;=20
    buf[1] =3D 0x01;=20
    buf[2] =3D 0x00;=20
    buf[3] =3D 0x03;=20
    buf[4] =3D l;=20
    for(x=3D0; x&lt;l; x++)
        buf[5+x] =3D hostname[x];=20
    x=3Dl+5;
    t =3D htons(port);
    memcpy((buf+x), &amp;t, 2);
    write(sockt, buf, x+2);
    read(sockt, buf, 1024);
    if((buf[0] =3D=3D 0x05) &amp;&amp; (buf[1] =3D=3D 0x00)) {
		portserv =3D htons(port);
		if(verbose) {
			printf("      OPEN\t\t%d",port);
			fflush(stdout);
		}
		if((service =3D getservbyport(portserv,"tcp"))) {
			printf("\t(%s)\n",service-&gt;s_name);
			fflush(stdout);	=09
		} else {=20
			printf("\t(unknown)\n");
			fflush(stdout);		=09
		}
		open_p[index_o++] =3D port;
		close(sockt);
		return 0;
    }
    if(verbose) {
		printf("      CLOSED|FILTRED\t\t%d\n",port);
		fflush(stdout);
	}
	closed_p[index_c++] =3D port;
	close(sockt);
	return 0;
}


int main(int argc, char **argv) {
	struct sockaddr_in sock;
	struct servent *se;
	struct timeval start, end;
	struct winsize term;
	char *portopt, *method;
	unsigned int mtime, seconds, useconds;
	int i, c, sockfd;
    progress =3D 1;
   =20
    bar progress;
    setupbar(&amp;progress);
    =09
    printf("[*] Network Scanner v1.0 starting at %s %s [*]\n",__TIME__,__DA=
TE__);
	srand ((unsigned) time(NULL));
	gettimeofday(&amp;start, NULL);
	signal(SIGINT, ctrlc);

    while (1) {
		static struct option long_options[] =3D {
			//{"verbose",  no_argument,       &amp;verbose,       1 },
			{"verbose",  no_argument,       0,             'v'},
            {"syn",      no_argument,       0,             's'},
            {"connect",  no_argument,       0,             'c'},
            {"tor",      no_argument,       0,             't'},
            {"udp",      no_argument,       0,             'u'},
            {"banner",   no_argument,       0,             'b'},
            {"help",     no_argument,       0,             'h'},
            {"delay",    required_argument, 0,             'd'},
            {"port",	 required_argument, 0,             'p'},
            {0, 0, 0, 0}
        };
        int option_index =3D 0;
        c =3D getopt_long (argc, argv, "scthvubd:p:", long_options, &amp;op=
tion_index);
        if (c =3D=3D -1)
			break;
		switch (c) {
            case 0:
				if (long_options[option_index].flag !=3D 0)
					break;
				printf ("option %s", long_options[option_index].name);
				if (optarg)
					printf (" with arg %s", optarg);
				break;
			case 's':
				if(getuid() !=3D 0) {
					printf("    [ERROR-PERMISSION] You must to be root\n");
					exit(0);
				}
				syn =3D 1;
				method =3D "synpacket";
				interface();
				sockfd =3D setupsock(sock);
				break;
            case 'c':
				conn =3D 1;
				method =3D "connect";
				break;
			case 't':
				tor =3D 1;
				method =3D "tor";
				break;
			case 'u':
				udp =3D 1;
				method =3D "udp";
				break;
			case 'b':
				banserv =3D 1;
				break;
            case 'd':
				delay =3D atoi(optarg);
				break;
			case 'p':
				portcontrol(optarg);
				portopt =3D optarg;
				break;
			case 'v':
				verbose =3D 1;
				//progress =3D 0;
				break;
			case 'h':
				help();
			case '?':
				help();
				break;
            default:
				help();
		}
	}
=09
    if (optind &lt; argc) {
		while (optind &lt; argc)
			hostname =3D argv[optind++];
    } else help();
   =20
    if(!(hostname =3D resolveHost(hostname))) {
        fprintf (stderr,"\n  [RESOLUTION-ERROR] Unable to resolve: %s\n\n",=
hostname);
        exit(0);
    }
   =20
    if ((syn &amp;&amp; tor &amp;&amp; conn &amp;&amp; udp) || (syn &amp;&a=
mp; conn) || (syn &amp;&amp; tor) || (tor &amp;&amp; conn))=20
		help();
	if ((udp &amp;&amp; syn &amp;&amp; conn) || (udp &amp;&amp; syn) || (udp &=
amp;&amp; conn) || (udp &amp;&amp; tor))
		help();
=09
	if (!syn &amp;&amp; !tor &amp;&amp; !conn &amp;&amp; !udp) {
		if(getuid() =3D=3D 0) {
			syn =3D 1;
			method =3D "synpacket";
			interface();
			sockfd =3D setupsock(sock);
		} else {
			conn =3D 1;
			method =3D "connect";
		}
	}
=09
	if (!rangeport &amp;&amp; !singleport &amp;&amp; !specificport)
		normal =3D 1;
=09
	if(!verbose) {
		ioctl(0, TIOCGWINSZ, &amp;term);
		if(term.ws_col &lt;  progress.width+10)
			verbose =3D 1;
	}
=09
	if (rangeport) {
		printf("    Host: %s  Method: %s  Port: [%d-%d]\n\n", hostname, method, m=
in, max);
		if(!verbose) {
			printf("    ");
			progress.max =3D max-min;
		}
		for(port=3Dmin, i=3D1; port&lt;max; port++, i++) {
			if(conn)
				setupsock(sock);
			if(tor)
				torscan();
			if(syn)
				synpacket(sockfd, sock);
			if(udp)
				udpscan(port);
			if(!verbose)
				progressbar(i, &amp;progress);
		}
	}
=09
	if (specificport) {
		printf("    Host: %s  Method: %s  Port: [", hostname, method);
		for(i=3D0; i&lt;index_p; i++) {
			printf("%d", ports[i]);
			if(i !=3D index_p-1)
				printf(",");
		}
		puts("]\n");
		if(!verbose) {
			printf("    ");
			progress.max =3D i-1;
		}
		for(i=3D0; i&lt;index_p; i++) {
			port =3D ports[i];
			if(conn)
				setupsock(sock);
			if(tor)
				torscan();
			if(syn)
				synpacket(sockfd, sock);
			if(udp)
				udpscan(port);
			if(!verbose)
				progressbar(i, &amp;progress);
		}
	}
=09
	if (singleport) {
		printf("    Host: %s  Method: %s  Port: [%s]\n", hostname, method, portop=
t);
		port =3D min;
		if(conn)
			setupsock(sock);
		if(tor)
			torscan();
		if(syn)
			synpacket(sockfd,sock);
		if(udp)
			udpscan(port);
	}
=09
	if (normal) {
		printf("    Host: %s  Method: %s  ports: [/etc/services]\n\n", hostname, =
method);	=09
		if(!verbose) {
			printf("    ");
			progress.max =3D 312;
			i =3D 0;
		}
		while((se =3D getservent())) {
			if(udp) {
				if(strcmp(se-&gt;s_proto, "udp") =3D=3D 0) {
					port =3D ntohs(se-&gt;s_port);
					udpscan(port);
					if(!verbose)
						progressbar(++i, &amp;progress);
				}
			}
			if(syn || conn || tor) {
				if(strcmp(se-&gt;s_proto, "tcp") =3D=3D 0) {
					port =3D ntohs(se-&gt;s_port);
					if(conn)
						setupsock(sock);
					if(tor)
						torscan();
					if(syn)
						synpacket(sockfd, sock);
					if(!verbose)
						progressbar(++i, &amp;progress);
				}
			}
		}
	}
	printf("\n\n");
	gettimeofday(&amp;end, NULL);
	seconds =3D end.tv_sec - start.tv_sec;
	useconds =3D end.tv_usec - end.tv_usec;
	mtime =3D ((seconds)*1000 + useconds/1000.0) +0.5;
	statistic();
	if((seconds/60) &gt; 0)
		printf("scanned in %d.%d.%d min\n", seconds/60,seconds%60,abs(mtime-(seco=
nds*1000)));
	else
		printf("scanned in %d.%d sec\n", seconds%60, abs(mtime-(seconds*1000)));
	return 0;
}


</div></body></html>
------MultipartBoundary--fM5v4o5hmMBPxhbnNPxFT7r0X6F3C1r0GqKsGRv9w0------
