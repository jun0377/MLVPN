#ifndef _MLVPN_PKT_H
#define _MLVPN_PKT_H

#include <stdint.h>
#include "crypto.h"

#define DEFAULT_MTU 1500

enum {
    MLVPN_PKT_AUTH,
    MLVPN_PKT_AUTH_OK,
    MLVPN_PKT_KEEPALIVE,
    MLVPN_PKT_DATA,
    MLVPN_PKT_DISCONNECT
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

#define PKTHDRSIZ(pkt) (sizeof(pkt)-sizeof(pkt.data))
#define ETH_OVERHEAD 24
#define IPV4_OVERHEAD 20
#define TCP_OVERHEAD 20
#define UDP_OVERHEAD 8

#define IP4_UDP_OVERHEAD (IPV4_OVERHEAD + UDP_OVERHEAD)

#endif
