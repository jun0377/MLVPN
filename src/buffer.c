/*
 * Copyright (c) 2015, Laurent COUSTET <ed@zehome.com>
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "buffer.h"
#include "mlvpn.h"

/**
  * Generic handlers
  */

/*
* 环形缓冲区的基础初始化函数 ，实现了通用的环形缓冲区创建逻辑
*/
circular_buffer_t *
mlvpn_cb_init(int size)
{
    circular_buffer_t *buf = calloc(1, sizeof(circular_buffer_t));  // 分配并清零环形缓冲区控制结构体
    buf->size = size + 1;                                           // 设置容量为size+1，多出的1个位置用于区分满/空状态
    buf->data = NULL;                                               // 初始化数据指针为NULL，由上层函数负责分配实际数据存储空间
    mlvpn_cb_reset(buf);                                            // 重置读写指针到初始位置（start=0, end=0）
    return buf;
}

/* Please note you MUST free yourself the data associated! */
void
mlvpn_cb_free(circular_buffer_t *buf)
{
    free(buf);
}

/* Re-initialize the ring buffer to default values */
void
mlvpn_cb_reset(circular_buffer_t *buf)
{
    buf->start = 0;
    buf->end = 0;
}

int
mlvpn_cb_is_full(const circular_buffer_t *buf)
{
    return (buf->end + 1) % buf->size == buf->start;
}

int
mlvpn_cb_is_empty(const circular_buffer_t *buf)
{
    return buf->end == buf->start;
}

/* Release and return the packet if available.
 * data must point to a valid location in memory
 * where the actual data is stored.
*/
void *
mlvpn_cb_read(circular_buffer_t *buf, void **data)
{
    void *ret = data[buf->start];
    buf->start = (buf->start + 1) % buf->size;
    return ret;
}


/* Register & return a new packet.
 * See comment in cb_read for **data signification.
 */
void *
mlvpn_cb_write(circular_buffer_t *buf, void **data)
{
    void *ret = data[buf->end];
    buf->end = (buf->end + 1) % buf->size;
    if (buf->end == buf->start)
        buf->start = (buf->start + 1) % buf->size;
    return ret;
}

/**
 * MLVPN数据包缓冲区初始化
 */
circular_buffer_t *
mlvpn_pktbuffer_init(int size)
{
    int i;
    /* Basic circular buffer allocation */
    circular_buffer_t *buf = mlvpn_cb_init(size);               // 创建基础环形缓冲区结构，分配size+1个元素的空间

    /* Actual packet buffer memory allocation */
    pktbuffer_t *pktbuf = calloc(1, sizeof(pktbuffer_t));       // 为数据包缓冲区结构体分配内存并初始化为0
    pktbuf->pkts = malloc(buf->size * sizeof(mlvpn_pkt_t *));   // 为数据包指针数组分配内存，数组大小为buf->size个指针

    // 遍历所有数据包指针位置，为每个数据包分配内存并初始化为0，每个包约1500+字节
    for(i = 0; i < buf->size; i++)
        pktbuf->pkts[i] = calloc(1, sizeof(mlvpn_pkt_t));

    buf->data = pktbuf;                                         // 将数据包缓冲区结构体关联到环形缓冲区的data字段
    /* This is sub-optimal as we call cb_free another time.
     * Not a big deal though. */
    mlvpn_pktbuffer_reset(buf);                                 // 重置缓冲区状态，将start和end指针归零
    return buf;
}

void
mlvpn_pktbuffer_free(circular_buffer_t *buf)
{
    pktbuffer_t *pktbuffer = buf->data;
    free(pktbuffer->pkts);
    mlvpn_cb_free(buf);
}

void
mlvpn_pktbuffer_reset(circular_buffer_t *buf)
{
    mlvpn_cb_reset(buf);
}

mlvpn_pkt_t *
mlvpn_pktbuffer_write(circular_buffer_t *buf)
{
    pktbuffer_t *pktbuffer = buf->data;
    mlvpn_pkt_t *pkt = (mlvpn_pkt_t *)mlvpn_cb_write(buf,
                       (void *)pktbuffer->pkts);
    /* Initialize the new packet to send */
    pkt->len = 0;
    pkt->type = MLVPN_PKT_DATA;
    return pkt;
}

mlvpn_pkt_t *
mlvpn_pktbuffer_read(circular_buffer_t *buf)
{
    pktbuffer_t *pktbuffer = buf->data;
    return (mlvpn_pkt_t *)mlvpn_cb_read(buf,
                                        (void *)pktbuffer->pkts);
}

/*
* 缓冲区初始化 ，用于MLVPN的数据包重排序功能
*/
freebuffer_t *
mlvpn_freebuffer_init(unsigned int size)
{
    unsigned int i;                                                 // 循环计数器
    struct pkt_entry *entry;                                        // 数据包条目指针，用于创建链表节点
    freebuffer_t *freebuf = calloc(size, sizeof(freebuffer_t));     // 分配freebuffer_t结构体内存
    if (freebuf == NULL) {
        fatal("buffer", "memory allocation failed");
    }
    freebuf->size = size;                                           // 设置缓冲区总容量
    freebuf->used = 0;                                              // 初始化已使用计数器为0
    TAILQ_INIT(&freebuf->free_head);                                // 初始化空闲数据包链表头
    TAILQ_INIT(&freebuf->used_head);                                // 初始化已使用数据包链表头

    // 预分配指定数量的数据包条目
    for(i = 0; i < size; i++) {
        entry = calloc(1, sizeof(struct pkt_entry));                // 为每个数据包条目分配内存
        if (entry == NULL) {
            fatal("buffer", "memory allocation failed");
        }
        TAILQ_INSERT_HEAD(&freebuf->free_head, entry, entries);     // 将新分配的条目插入到空闲链表的头部，这样所有预分配的数据包都在空闲状态
    }
    return freebuf;
}

void
mlvpn_freebuffer_reset(freebuffer_t *freebuf) 
{
    struct pkt_entry *entry;
    while(!TAILQ_EMPTY(&freebuf->used_head)) {
        entry = TAILQ_FIRST(&freebuf->used_head);
        TAILQ_REMOVE(&freebuf->used_head, entry, entries);
        TAILQ_INSERT_HEAD(&freebuf->free_head, entry, entries);
    }
    freebuf->used = 0;
}

mlvpn_pkt_t *
mlvpn_freebuffer_get(freebuffer_t *freebuf)
{
    struct pkt_entry *entry = TAILQ_FIRST(&freebuf->free_head);
    if (entry) {
        TAILQ_REMOVE(&freebuf->free_head, entry, entries);
        TAILQ_INSERT_TAIL(&freebuf->used_head, entry, entries);
        freebuf->used++;
        return &entry->pkt;
    } else {
        return NULL;
    }
}

mlvpn_pkt_t *
mlvpn_freebuffer_drain_used(freebuffer_t *freebuf)
{
    /* We get the elements in reverse order there... Not ideal */
    struct pkt_entry *entry = TAILQ_FIRST(&freebuf->used_head);
    if (entry) {
        TAILQ_REMOVE(&freebuf->used_head, entry, entries);
        TAILQ_INSERT_HEAD(&freebuf->free_head, entry, entries);
        freebuf->used--;
        return &entry->pkt;
    } else {
        return NULL;
    }
}

void
mlvpn_freebuffer_free(freebuffer_t *freebuf, mlvpn_pkt_t *pkt)
{
    struct pkt_entry *entry;
    mlvpn_pkt_t *p;
    TAILQ_FOREACH(entry, &freebuf->used_head, entries)
    {
        p = &entry->pkt;
        if (p == pkt) {
            TAILQ_REMOVE(&freebuf->used_head, entry, entries);
            TAILQ_INSERT_HEAD(&freebuf->free_head, entry, entries);
            freebuf->used--;
            return;
        }
    }
    fatalx("freebuffer_free could not find the packet you gave me.");
}