#ifndef _MLVPN_H
#define _MLVPN_H

#include "includes.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <math.h>
#include <ev.h>

/* Many thanks Fabien Dupont! */
#ifdef HAVE_LINUX
 /* Absolutely essential to have it there for IFNAMSIZ */
 #include <sys/types.h>
 #include <netdb.h>
 #include <linux/if.h>
#endif

#include <arpa/inet.h>

#ifdef HAVE_VALGRIND_VALGRIND_H
 #include <valgrind/valgrind.h>
#else
 #define RUNNING_ON_VALGRIND 0
#endif

#ifdef HAVE_DECL_RES_INIT
 #include <netinet/in.h>
 #include <arpa/nameser.h>
 #include <resolv.h>
#endif

#ifdef HAVE_FILTERS
 #include <pcap/pcap.h>
#endif

#include "pkt.h"
#include "buffer.h"
#include "reorder.h"
#include "timestamp.h"

#define MLVPN_MAXHNAMSTR 256
#define MLVPN_MAXPORTSTR 6

/* Number of packets in the queue. Each pkt is ~ 1520 */
/* 1520 * 128 ~= 24 KBytes of data maximum per channel VMSize */
#define PKTBUFSIZE 1024

/* tuntap interface name size */
#ifndef IFNAMSIZ
 #define IFNAMSIZ 16
#endif
#define MLVPN_IFNAMSIZ IFNAMSIZ

/* How frequently we check tunnels */
#define MLVPN_IO_TIMEOUT_DEFAULT 1.0
/* What is the maximum retry timeout */
#define MLVPN_IO_TIMEOUT_MAXIMUM 60.0
/* In case we can't open the tunnel, retry every time with previous
 * timeout multiplied by the increment.
 * Example:
 * 1st try t+0: bind error
 * 2nd try t+1: bind error
 * 3rd try t+2: bind error
 * 4rd try t+4: dns error
 * ...
 * n try t+60
 * n+1 try t+60
 */
#define MLVPN_IO_TIMEOUT_INCREMENT 2

#define NEXT_KEEPALIVE(now, t) (now + 1)
/* Protocol version of mlvpn
 * version 0: mlvpn 2.0 to 2.1 
 * version 1: mlvpn 2.2+ (add reorder field in mlvpn_proto_t)
 */
#define MLVPN_PROTOCOL_VERSION 1

struct mlvpn_options_s
{
    /* use ps_status or not ? */
    int change_process_title;                                   // 是否允许进程更改名称
    /* process name if set */
    char process_name[1024];                                    // 自定义进程名称字符串（最大1024字节）
    /* where is the config file */
    char control_unix_path[MAXPATHLEN];                         // Unix域套接字控制接口路径（最大路径长度MAXPATHLEN），用于本地进程间通信，允许外部工具控制MLVPN实例
    char control_bind_host[MLVPN_MAXHNAMSTR];                   // bind IP
    char control_bind_port[MLVPN_MAXHNAMSTR];                   // bind Port
    char config_path[MAXPATHLEN];                               // 配置文件的完整路径
    /* tunnel configuration for the status command script */
    char ip4[24];
    char ip6[128]; /* Should not exceed 45 + 3 + 1 bytes */
    char ip4_gateway[16];
    char ip6_gateway[128];
    char ip4_routes[4096]; /* Allow about 200 routes minimum */ // IPv4路由表配置，约支持200条路由的最小配置
    char ip6_routes[8192]; /* Allow about 80 routes minimum */  // Pv6路由表配置，约支持80条路由的最小配置
    int mtu;
    int config_fd;                                              // 配置文件的文件描述符
    /* log verbosity */
    int verbose;                                                // 日志详细程度级别， 0: 基本日志, 1: 包含info, 2: 包含特定debug, >2: 全部debug
    int debug;                                                  // 1: 调试模式（输出到stderr）, 0: 生产模式（输出到syslog）
    /* User change if running as root */
    char unpriv_user[128];                                      // 非特权用户名（128字节），当以root启动时，初始化完成后切换到此用户身份运行，提高安全性，遵循最小权限原则
    int cleartext_data;                                         // 1: 允许明文传输（调试用）, 0: 强制加密传输（生产环境）
    int root_allowed;                                           // 是否允许root用户运行
    uint32_t reorder_buffer_size;                               // 数据包重排序缓冲区大小（32位无符号整数），// 用于处理网络中乱序到达的数据包，提高传输可靠性
    uint32_t fallback_available;                                // 备用链路可用性标志（32位无符号整数），指示是否有备用隧道可用于故障转移
};

struct mlvpn_status_s
{
    int fallback_mode;
    int connected;
    int initialized;
    time_t start_time;
    time_t last_reload;
};

enum chap_status {
    MLVPN_DISCONNECTED,
    MLVPN_AUTHSENT,
    MLVPN_AUTHOK,
    MLVPN_LOSSY,
    MLVPN_HIGH_LATENCY
};

LIST_HEAD(rtunhead, mlvpn_tunnel_s);

extern struct rtunhead rtuns;           // tun隧道链表头

typedef struct mlvpn_tunnel_s
{
    LIST_ENTRY(mlvpn_tunnel_s) entries;
    char *name;           /* tunnel name */
    char bindaddr[MLVPN_MAXHNAMSTR]; /* packets source */
    char bindport[MLVPN_MAXPORTSTR]; /* packets port source (or NULL) */
    uint32_t bindfib;     /* FIB number to use */
    char destaddr[MLVPN_MAXHNAMSTR]; /* remote server ip (can be hostname) */
    char destport[MLVPN_MAXPORTSTR]; /* remote server port */
    int fd;               /* socket file descriptor */
    int server_mode;      /* server or client */
    int disconnects;      /* is it stable ? */
    int conn_attempts;    /* connection attempts */
    int fallback_only;    /* if set, this link will be used when all others are down */
    uint32_t loss_tolerence; /* How much loss is acceptable before the link is discarded */
    uint32_t latency_tolerence; /* How much latency is acceptable before the link is discarded */
    uint64_t seq;
    uint64_t expected_receiver_seq;
    uint64_t saved_timestamp;
    uint64_t saved_timestamp_received_at;
    uint64_t seq_last;
    uint64_t seq_vect;
    int rtt_hit;
    double srtt;
    double rttvar;
    double weight;        /* For weight round robin */
    uint32_t flow_id;
    uint64_t sentpackets; /* 64bit packets sent counter */
    uint64_t recvpackets; /* 64bit packets recv counter */
    uint64_t sentbytes;   /* 64bit bytes sent counter */
    uint64_t recvbytes;   /* 64bit bytes recv counter */
    uint32_t timeout;     /* configured timeout in seconds */
    uint32_t bandwidth;   /* bandwidth in bytes per second */
    circular_buffer_t *sbuf;    /* send buffer */
    circular_buffer_t *hpsbuf;  /* high priority buffer */
    struct addrinfo *addrinfo;
    enum chap_status status;    /* Auth status */
    ev_tstamp last_activity;
    ev_tstamp last_connection_attempt;
    ev_tstamp next_keepalive;
    ev_tstamp last_keepalive_ack;
    ev_tstamp last_keepalive_ack_sent;
    ev_io io_read;
    ev_io io_write;
    ev_timer io_timeout;
} mlvpn_tunnel_t;

#ifdef HAVE_FILTERS
struct mlvpn_filters_s {
    uint8_t count;
    struct bpf_program filter[255];
    mlvpn_tunnel_t *tun[255];
};
#endif

int mlvpn_config(int config_file_fd, int first_time);
int mlvpn_sock_set_nonblocking(int fd);

int mlvpn_loss_ratio(mlvpn_tunnel_t *tun);
int mlvpn_rtun_wrr_reset(struct rtunhead *head, int use_fallbacks);
mlvpn_tunnel_t *mlvpn_rtun_wrr_choose();
mlvpn_tunnel_t *mlvpn_rtun_choose();
mlvpn_tunnel_t *mlvpn_rtun_new(const char *name,
    const char *bindaddr, const char *bindport, uint32_t bindfib,
    const char *destaddr, const char *destport,
    int server_mode, uint32_t timeout,
    int fallback_only, uint32_t bandwidth,
    uint32_t loss_tolerence, uint32_t latency_tolerence);
void mlvpn_rtun_drop(mlvpn_tunnel_t *t);
void mlvpn_rtun_status_down(mlvpn_tunnel_t *t);
#ifdef HAVE_FILTERS
int mlvpn_filters_add(const struct bpf_program *filter, mlvpn_tunnel_t *tun);
mlvpn_tunnel_t *mlvpn_filters_choose(uint32_t pktlen, const u_char *pktdata);
#endif

#include "privsep.h"
#include "log.h"

#endif
