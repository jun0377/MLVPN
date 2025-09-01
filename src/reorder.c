/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Adapted for mlvpn by Laurent Coustet (c) 2015
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>

#include "reorder.h"
#include "log.h"

/* A generic circular buffer */
struct cir_buffer {
    unsigned int size;   /*     容量    *< Number of pkts that can be stored */
    unsigned int mask;   /*     用户回绕计算    *< [buffer_size - 1]: used for wrap-around */
    unsigned int head;   /*     插入点      *< insertion point in buffer */
    unsigned int tail;   /*     读取点      *< extraction point in buffer */
    mlvpn_pkt_t **pkts;
};

/* The reorder buffer data structure itself */
struct mlvpn_reorder_buffer {
    uint64_t min_seqn;              /*  最小序列号                  *< Lowest seq. number that can be in the buffer */
    unsigned int memsize;           /*  重排序缓冲区内存大小        *< memory area size of reorder buffer */
    struct cir_buffer ready_buf;    /*  已排序数据包临时缓冲区      *< temp buffer for dequeued pkts */
    struct cir_buffer order_buf;    /*  重排序缓冲区                *< buffer used to reorder pkts */
    int is_initialized;
};

// 初始化重排序缓冲区
struct mlvpn_reorder_buffer *
mlvpn_reorder_init(struct mlvpn_reorder_buffer *b, unsigned int bufsize,
        unsigned int size)
{
    const unsigned int min_bufsize = sizeof(*b) +
                    (2 * size * sizeof(mlvpn_pkt_t *));
    if (b == NULL) {
        log_crit("reorder", "Invalid reorder buffer parameter: NULL");
        return NULL;
    }
    if (bufsize < min_bufsize) {
        log_crit("reorder", "Invalid reorder buffer memory size: %u, "
            "minimum required: %u", bufsize, min_bufsize);
        return NULL;
    }

    memset(b, 0, bufsize);
    b->memsize = bufsize;
    b->order_buf.size = b->ready_buf.size = size;
    b->order_buf.mask = b->ready_buf.mask = size - 1;
    b->ready_buf.pkts = (void *)&b[1];
    b->order_buf.pkts = (void *)&b[1] + (size * sizeof(b->ready_buf.pkts[0]));

    return b;
}

// 创建重排序缓冲区
struct mlvpn_reorder_buffer*
mlvpn_reorder_create(unsigned int size)
{
    struct mlvpn_reorder_buffer *b = NULL;

    // 缓冲取结构体本身 + 两个缓冲队列(ready_buf+order_buf)
    const unsigned int bufsize = sizeof(struct mlvpn_reorder_buffer) +
                    (2 * size * sizeof(mlvpn_pkt_t *));
    /* Allocate memory to store the reorder buffer structure. */
    b = calloc(1, bufsize);
    if (b == NULL) {
        log_crit("reorder", "Memzone allocation failed");
    } else {
        mlvpn_reorder_init(b, bufsize, size);
    }
    return b;
}

// 重置缓冲区状态,重新初始化现有的重排序缓冲区，清楚所有缓存的数据包和状态信息
void
mlvpn_reorder_reset(struct mlvpn_reorder_buffer *b)
{
    mlvpn_reorder_init(b, b->memsize, b->order_buf.size);
}

// 释放缓冲区内存
void
mlvpn_reorder_free(struct mlvpn_reorder_buffer *b)
{
    /* Check user arguments. */
    if (b == NULL)
        return;
    free(b);
}


/*
* 重排序溢出处理函数,用于处理数据包序列号超出当前窗口范围的情况
* 当新到达的数据包序列号超出当前重排序窗口时，该函数负责：
*   1. 移动窗口 ：将重排序缓冲区的窗口向前移动
*   2. 转移数据包 ：将已排序的数据包从 order_buf 转移到 ready_buf
*   3. 跳过缺失 ：跳过丢失或延迟的数据包
*   4. 更新状态 ：更新最小序列号和缓冲区指针
*/
// n - 需要移动的最小数据包数量
static unsigned
mlvpn_reorder_fill_overflow(struct mlvpn_reorder_buffer *b, unsigned n)
{
    /*
     * 1. Move all ready pkts that fit to the ready_buf
     * 2. check if we meet the minimum needed (n).
     * 3. If not, then skip any gaps and keep moving.
     * 4. If at any point the ready buffer is full, stop
     * 5. Return the number of positions the order_buf head has moved
     */

    struct cir_buffer *order_buf = &b->order_buf,
            *ready_buf = &b->ready_buf;

    // 记录 order_buf 头指针移动的总位置数
    unsigned int order_head_adv = 0;

    /*
     * move at least n packets to ready buffer, assuming ready buffer
     * has room for those packets.
     */

    // 移动至少 n 个数据包到 ready buffer，前提是 ready buffer 有足够空间
    while (order_head_adv < n &&
            ((ready_buf->head + 1) & ready_buf->mask) != ready_buf->tail) {

        /* if we are blocked waiting on a packet, skip it */
        // 当前位置是空的，跳过
        if (order_buf->pkts[order_buf->head] == NULL) {
            order_buf->head = (order_buf->head + 1) & order_buf->mask;
            order_head_adv++;
        }

        /* Move all ready pkts that fit to the ready_buf */
        // 移动所有连续可用的数据包到 ready buffer
        while (order_buf->pkts[order_buf->head] != NULL) {

            // 数据包从 order buffer 转移到 ready buffer
            ready_buf->pkts[ready_buf->head] =
                    order_buf->pkts[order_buf->head];

            order_buf->pkts[order_buf->head] = NULL;
            order_head_adv++;

            // order buffer前进
            order_buf->head = (order_buf->head + 1) & order_buf->mask;

            // ready buffer 将满
            if (((ready_buf->head + 1) & ready_buf->mask) == ready_buf->tail)
                break;

            // ready buffer 前进
            ready_buf->head = (ready_buf->head + 1) & ready_buf->mask;
        }
    }

    // 更新最小序列号
    b->min_seqn += order_head_adv;
    /* Return the number of positions the order_buf head has moved */
    return order_head_adv;
}

/*
*   重排序模块的核心插入函数，负责将新到达的数据包按序列号插入到重排序缓冲区的正确位置
*/
int
mlvpn_reorder_insert(struct mlvpn_reorder_buffer *b, mlvpn_pkt_t *pkt)
{
    uint64_t offset;                                // 相较于当前最小序列号的偏移量
    uint32_t position;                              // 在缓冲区中的实际位置
    struct cir_buffer *order_buf = &b->order_buf;   // 重排序缓冲区

    // 初始化，使用第一个数据包的序列号作为起始点
    if (!b->is_initialized) {
        b->min_seqn = pkt->seq;
        b->is_initialized = 1;
        log_debug("reorder", "initial sequence: %"PRIu64"", pkt->seq);
    }

    /*
     * calculate the offset from the head pointer we need to go.
     * The subtraction takes care of the sequence number wrapping.
     * For example (using 16-bit for brevity):
     *  min_seqn  = 0xFFFD
     *  pkt_seq   = 0x0010
     *  offset    = 0x0010 - 0xFFFD = 0x13
     */
    /*
     * 计算从头指针需要移动的偏移量
     * 减法操作自动处理序列号回绕情况
     * 例如（使用16位简化说明）：
     *  min_seqn  = 0xFFFD
     *  pkt_seq   = 0x0010  
     *  offset    = 0x0010 - 0xFFFD = 0x13
     */
    offset = pkt->seq - b->min_seqn;

    /*
     * action to take depends on offset.
     * offset < buffer->size: the pkt fits within the current window of
     *    sequence numbers we can reorder. EXPECTED CASE.
     * offset > buffer->size: the pkt is outside the current window. There
     *    are a number of cases to consider:
     *    1. The packet sequence is just outside the window, then we need
     *       to see about shifting the head pointer and taking any ready
     *       to return packets out of the ring. If there was a delayed
     *       or dropped packet preventing drains from shifting the window
     *       this case will skip over the dropped packet instead, and any
     *       packets dequeued here will be returned on the next drain call.
     *    2. The packet sequence number is vastly outside our window, taken
     *       here as having offset greater than twice the buffer size. In
     *       this case, the packet is probably an old or late packet that
     *       was previously skipped, so just enqueue the packet for
     *       immediate return on the next drain call, or else return error.
     */
    /*
    * 采取的操作取决于偏移量。
    * 偏移量 < buffer->size：数据包位于我们可以重新排序的当前序列号窗口内。这是预期的情况。
    * 偏移量 > buffer->size：数据包超出了当前窗口。有几种情况需要考虑：
    * 1. 数据包序列刚好在窗口外，那么我们需要考虑移动头指针，并将任何准备返回的数据包从环中取出。
    *    如果有延迟或丢失的数据包阻止了窗口的移动，这种情况下将跳过丢失的数据包，而在此出队的任何
    *    数据包将在下一个排空调用时返回。
    * 2. 数据包序列号大大超出我们的窗口，此处定义为偏移量大于缓冲区大小的两倍。在这种情况下，
    *    数据包可能是之前跳过的旧数据包或迟到的数据包，因此只需将数据包入队以便在下一个排空调用时立即返回，
    *    否则返回错误。
    */
    // 情况1：数据包在当前重排序窗口内（期望情况）,正常网络抖动
    if (offset < b->order_buf.size) {
        position = (order_buf->head + offset) & order_buf->mask;
        order_buf->pkts[position] = pkt;
    } 
    // 情况2：数据包刚好超出当前窗口，但在可接受范围内，中等延迟、乱序
    else if (offset < 2 * b->order_buf.size) {
        // 调用溢出处理函数，尝试移动窗口
        if (mlvpn_reorder_fill_overflow(b, offset + 1 - order_buf->size)
                < (offset + 1 - order_buf->size)) {
            /* Put in handling for enqueue straight to output */
            return -1;
        }
        offset = pkt->seq - b->min_seqn;
        position = (order_buf->head + offset) & order_buf->mask;
        order_buf->pkts[position] = pkt;
    } 
    // 情况3：数据包序列号远超出窗口范围，严重延迟、丢包
    else {
        /* Put in handling for enqueue straight to output */
        log_debug("reorder", "packet sequence out of range");
        return -2;
    }
    return 0;
}

/*
*   重排序模块的核心输入函数，从重排序缓冲区中提取已排序的数据包
*/
unsigned int
mlvpn_reorder_drain(struct mlvpn_reorder_buffer *b, mlvpn_pkt_t **pkts,
        unsigned max_pkts)
{   
    // 已提取的数据包计数器
    unsigned int drain_cnt = 0;

    struct cir_buffer *order_buf = &b->order_buf,
            *ready_buf = &b->ready_buf;

    /* Try to fetch requested number of pkts from ready buffer */
    /* 尝试从就绪缓冲区获取请求数量的数据包 */
    while ((drain_cnt < max_pkts) && (ready_buf->tail != ready_buf->head)) {
        pkts[drain_cnt++] = ready_buf->pkts[ready_buf->tail];
        ready_buf->tail = (ready_buf->tail + 1) & ready_buf->mask;
    }

    /*
     * If requested number of buffers not fetched from ready buffer, fetch
     * remaining buffers from order buffer
     */
    // 如果从就绪缓冲区未获取到足够数量的数据包,则从重排序缓冲区获取剩余的数据包
    while ((drain_cnt < max_pkts) &&
            (order_buf->pkts[order_buf->head] != NULL)) {
        pkts[drain_cnt++] = order_buf->pkts[order_buf->head];
        order_buf->pkts[order_buf->head] = NULL;
        b->min_seqn++;
        order_buf->head = (order_buf->head + 1) & order_buf->mask;
    }
    return drain_cnt;
}
