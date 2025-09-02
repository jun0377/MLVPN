#ifndef _MLVPN_PKT_H
#define _MLVPN_PKT_H

#include <stdint.h>
#include "crypto.h"

#define DEFAULT_MTU 1500

enum {
    MLVPN_PKT_AUTH,             // 认证请求包：客户端向服务器发送的身份验证请求
                                // 包含加密的认证凭据，用于建立安全隧道连接
                                // 通常在连接建立阶段的第一步发送

    MLVPN_PKT_AUTH_OK,          // 认证确认包：服务器向客户端发送的认证成功响应
                                // 表示身份验证通过，隧道连接已建立
                                // 客户端收到此包后可开始发送数据流量

    MLVPN_PKT_KEEPALIVE,        // 心跳保活包：用于检测隧道连接的活跃状态
                                // 定期发送以防止NAT/防火墙超时断开连接
                                // 同时用于测量RTT和检测网络质量

    MLVPN_PKT_DATA,             // 数据传输包：承载实际用户网络流量的数据包
                                // 包含从TUN/TAP设备读取的IP数据包
                                // 这是MLVPN隧道中最主要的数据包类型

    MLVPN_PKT_DISCONNECT        // 断开连接包：通知对端即将关闭隧道连接
                                // 用于优雅地终止连接，清理资源
                                // 避免连接异常中断导致的资源泄漏
};

// MLVPN数据包结构
typedef struct {
    uint16_t len;                   // 数据包长度
    uint8_t type;                   // 数据包类型（认证、数据、心跳等）
    uint8_t reorder;                // 是否需要重排序
    uint64_t seq;                   // 序列号
    char data[DEFAULT_MTU];         // 实际数据内容（默认1500字节）
} mlvpn_pkt_t;


/* packet sent on the wire. 20 bytes headers for mlvpn */
// 20字节的包头 + 1500 MTU
typedef struct {
    uint16_t len;
    uint16_t version: 4; /* protocol version */
    uint16_t flags: 6;   /* protocol options */
    uint16_t reorder: 1; /* do reordering or not */
    uint16_t unused: 5;  /* not used for now */
    uint16_t timestamp;
    uint16_t timestamp_reply;
    uint32_t flow_id;
    uint64_t seq;         /* Stream sequence per flow (for crypto) */
    uint64_t data_seq;    /* data packets global sequence */
    char data[DEFAULT_MTU];
} __attribute__((packed)) mlvpn_proto_t;

// MLVPN包头长度，固定为 20byte
#define PKTHDRSIZ(pkt) (sizeof(pkt)-sizeof(pkt.data))
#define ETH_OVERHEAD 24
#define IPV4_OVERHEAD 20
#define TCP_OVERHEAD 20
#define UDP_OVERHEAD 8

#define IP4_UDP_OVERHEAD (IPV4_OVERHEAD + UDP_OVERHEAD)

#endif
