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

/**
 * MLVPN 全局状态结构体
 * 用于跟踪和管理整个 VPN 服务的运行状态信息
 */
struct mlvpn_status_s
{
    int fallback_mode;          // 备用模式标志：1表示当前运行在备用模式（主要链路不可用），0表示正常模式
    int connected;              // 连接状态标志：表示当前有多少个隧道处于已连接状态（MLVPN_AUTHOK及以上状态）
    int initialized;            // 初始化状态标志：1表示MLVPN服务已完成初始化，0表示尚未初始化完成
    time_t start_time;          // 服务启动时间戳：记录MLVPN服务启动的Unix时间戳，用于计算运行时长
    time_t last_reload;         // 最后重载时间戳：记录最后一次重新加载配置文件的Unix时间
};

// CHAP认证状态
enum chap_status {
    MLVPN_DISCONNECTED,     // 0 - 断开连接状态：隧道未建立连接或连接已断开
    MLVPN_AUTHSENT,         // 1 - 认证发送状态：已发送认证请求，等待服务器响应
    MLVPN_AUTHOK,           // 2 - 认证成功状态：认证通过，隧道连接正常，可以传输数据
    MLVPN_LOSSY,            // 3 - 丢包状态：连接存在但丢包率超过容忍阈值，影响传输质量
    MLVPN_HIGH_LATENCY      // 4 - 高延迟状态：连接存在但延迟超过容忍阈值，影响实时性
};

LIST_HEAD(rtunhead, mlvpn_tunnel_s);

extern struct rtunhead rtuns;           // tun隧道链表头

// MLVPN 的核心数据结构，表示一个网络隧道连接的完整状态和配置信息
typedef struct mlvpn_tunnel_s
{
    LIST_ENTRY(mlvpn_tunnel_s) entries;     // 链表节点，用于将此隧道结构体链接到全局隧道链表中，实现多隧道管理
    char *name;                             // 隧道名称指           /* tunnel name */
    char bindaddr[MLVPN_MAXHNAMSTR];        // 源地址               /* packets source */
    char bindport[MLVPN_MAXPORTSTR];        // 端口号               /* packets port source (or NULL) */
    uint32_t bindfib;                       // 路由表               /* FIB number to use */
    char destaddr[MLVPN_MAXHNAMSTR];        // 隧道的远程IP        /* remote server ip (can be hostname) */
    char destport[MLVPN_MAXPORTSTR];        // 隧道的远程端口       /* remote server port */
    int fd;                                 // 网络通信的底层socket /* socket file descriptor */
    int server_mode;                        // 工作模式标志：1表示服务器模式（监听连接），0表示客户端模式（主动连接） /* server or client */
    int disconnects;                        // 断开连接次数计数器   /* is it stable ? */
    int conn_attempts;                      // 连接尝试次数计数器   /* connection attempts */
    int fallback_only;                      // 备用链路标志：1表示仅在其他所有链路都断开时才使用此隧道      /* if set, this link will be used when all others are down */
    uint32_t loss_tolerence;                // 丢包容忍度阈值，超过此值的丢包率将导致链路被标记为不可用     /* How much loss is acceptable before the link is discarded */
    uint32_t latency_tolerence;             // 延迟容忍度阈值（毫秒），超过此值的延迟将导致链路被标记为高延迟状态/* How much latency is acceptable before the link is discarded */
    uint64_t seq;                           // 发送序列号，用于数据包排序和重复检测，每发送一个数据包递增
    uint64_t expected_receiver_seq;         // 期望接收的序列号，用于检测数据包丢失和乱序
    uint64_t saved_timestamp;               // 保存的时间戳，用于RTT（往返时间）计算和性能监控
    uint64_t saved_timestamp_received_at;   // 时间戳接收时间，记录何时收到带时间戳的数据包，用于延迟计算
    uint64_t seq_last;                      // 最后接收到的序列号，用于序列号连续性检查
    uint64_t seq_vect;                      // 序列号向量，用位图方式记录最近64个数据包的接收状态，用于丢包统计
    int rtt_hit;                            // RTT命中标志，表示是否成功测量到往返时间
    double srtt;                            // 平滑往返时间（Smoothed Round Trip Time），使用指数加权移动平均算法计算
    double rttvar;                          // RTT变化量（Round Trip Time Variation），用于计算RTT的标准差
    double weight;                          // 权重值，用于加权轮询算法中的负载均衡，权重越高分配的流量越多/* For weight round robin */
    uint32_t flow_id;                       // 流标识符，用于标识和跟踪特定的数据流
    uint64_t sentpackets;                   // 64位发送数据包计数器，记录通过此隧道发送的数据包总数 /* 64bit packets sent counter */
    uint64_t recvpackets;                   // 64位接收数据包计数器，记录通过此隧道接收的数据包总数 /* 64bit packets recv counter */
    uint64_t sentbytes;                     // 64位发送字节计数器，记录通过此隧道发送的字节总数 /* 64bit bytes sent counter */
    uint64_t recvbytes;                     // 64位接收字节计数器，记录通过此隧道接收的字节总数 /* 64bit bytes recv counter */
    uint32_t timeout;                       // 配置的超时时间（秒），用于连接超时和keepalive检测    /* configured timeout in seconds */
    uint32_t bandwidth;                     // 带宽限制（字节/秒），用于流量控制和QoS管理   /* bandwidth in bytes per second */
    circular_buffer_t *sbuf;                // 发送缓冲区指针，指向环形缓冲区结构，用于缓存待发送的数据包   /* send buffer */
    circular_buffer_t *hpsbuf;              // 高优先级发送缓冲区指针，用于缓存需要优先发送的数据包（如控制消息）   /* high priority buffer */
    struct addrinfo *addrinfo;              // 地址信息结构指针，包含解析后的网络地址信息，用于socket连接
    enum chap_status status;                // 隧道认证状态枚举，包括：DISCONNECTED(断开)、AUTHSENT(认证中)、AUTHOK(认证成功)、LOSSY(丢包)、HIGH_LATENCY(高延迟)     /* Auth status */
    ev_tstamp last_activity;                // 最后活动时间戳，记录最后一次收到数据包的时间，用于连接活性检测
    ev_tstamp last_connection_attempt;      // 最后连接尝试时间戳，记录最后一次尝试建立连接的时间
    ev_tstamp next_keepalive;               // 下次keepalive发送时间戳，用于定期发送保活消息
    ev_tstamp last_keepalive_ack;           // 最后keepalive确认时间戳，记录最后一次收到keepalive响应的时间
    ev_tstamp last_keepalive_ack_sent;      // 最后keepalive确认发送时间戳，记录最后一次发送keepalive响应的时间
    ev_io io_read;                          // libev读事件监听器，用于异步监听socket的可读事件
    ev_io io_write;                         // libev写事件监听器，用于异步监听socket的可写事件
    ev_timer io_timeout;                    // libev定时器，用于处理连接超时、keepalive等定时任务
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
