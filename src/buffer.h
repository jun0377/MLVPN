#ifndef _MLVPN_BUFFER_H
#define _MLVPN_BUFFER_H

#include <sys/types.h>
#include <sys/queue.h>
#include "pkt.h"

/* Basic circular buffer
 * data can be stored inside the struct, but that's not mandatory.
 * data is not used directly by mlvpn_cb_*.
 */
typedef struct
{
    int size;                       // 缓冲区总容量（实际分配 size+1 个元素空间）
    int start;                      // 读指针位置，指向下一个要读取的元素索
    int end;                        // 写指针位置，指向下一个要写入的元素索引
    void *data;                     // 指向实际数据存储区域的通用指针
} circular_buffer_t;

/**
pktbuffer_t
├── pkts ──→ [ptr0] ──→ mlvpn_pkt_t (约1500+字节)
             [ptr1] ──→ mlvpn_pkt_t (约1500+字节)
             [ptr2] ──→ mlvpn_pkt_t (约1500+字节)
             [...]
             [ptrN] ──→ mlvpn_pkt_t (约1500+字节)
 */
typedef struct
{
    mlvpn_pkt_t **pkts;     // 通过二级指针确保类型安全，避免 void* 的类型转换问题
} pktbuffer_t;

/*
* 包装器模式：
*   数据封装 : 将 mlvpn_pkt_t 包装在一个可链表化的结构中
*   功能扩展 : 为原本独立的数据包添加了链表管理能力
*   内存池支持 : 使得数据包可以在不同状态的链表间移动
*/
struct pkt_entry {
    mlvpn_pkt_t pkt;                            // MLVPN数据包
    TAILQ_ENTRY(pkt_entry) entries;             // 双向链表节点信息
};

typedef struct {
    uint32_t size;                              // 容量-节点个数
    uint32_t used;                              // 已使用的节点个数
    TAILQ_HEAD(, pkt_entry) free_head;          // 空闲节点
    TAILQ_HEAD(, pkt_entry) used_head;          // 已使用的节点
} freebuffer_t;

/**
 * Generic circular buffer handling
 */

/* Allocate a circular of size +1 element of sizememb length */
circular_buffer_t *
mlvpn_cb_init(int size);

void
mlvpn_cb_free(circular_buffer_t *buf);

void
mlvpn_cb_reset(circular_buffer_t *buf);

int
mlvpn_cb_is_full(const circular_buffer_t *buf);

int
mlvpn_cb_is_empty(const circular_buffer_t *buf);

void *
mlvpn_cb_read(circular_buffer_t *buf, void **data);

void *
mlvpn_cb_read_norelease(const circular_buffer_t *buf, void **data);

void *
mlvpn_cb_write(circular_buffer_t *buf, void **data);

/**
 * Application specific cirtular buffer handlers
 */

circular_buffer_t *
mlvpn_pktbuffer_init(int size);

void
mlvpn_pktbuffer_free(circular_buffer_t *buf);

void
mlvpn_pktbuffer_reset(circular_buffer_t *buf);

mlvpn_pkt_t *
mlvpn_pktbuffer_read(circular_buffer_t *buf);

mlvpn_pkt_t *
mlvpn_pktbuffer_read_norelease(circular_buffer_t *buf);

mlvpn_pkt_t *
mlvpn_pktbuffer_write(circular_buffer_t *buf);


/**
 * Single allocation buffers (used for reordering)
 */
freebuffer_t *
mlvpn_freebuffer_init(uint32_t size);

void
mlvpn_freebuffer_reset(freebuffer_t *freebuf);

mlvpn_pkt_t *
mlvpn_freebuffer_get(freebuffer_t *freebuf);

void
mlvpn_freebuffer_free(freebuffer_t *freebuf, mlvpn_pkt_t *pkt);

mlvpn_pkt_t *
mlvpn_freebuffer_drain_used(freebuffer_t *freebuf);

#endif
