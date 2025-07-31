#include "mlvpn.h"

/**
 * MLVPN TUN/TAP设备通用读取处理函数
 * 功能：处理从TUN/TAP设备读取的数据包，选择合适的隧道并加入发送队列
 * 参数：data - 数据包内容指针，len - 数据包长度
 * 返回值：处理的数据包长度
 */
int
mlvpn_tuntap_generic_read(u_char *data, uint32_t len)
{
    circular_buffer_t *sbuf = NULL;         // 发送缓冲区
    mlvpn_tunnel_t *rtun = NULL;            // 选中的隧道
    mlvpn_pkt_t *pkt;                       // 数据包

#ifdef HAVE_FILTERS
    rtun = mlvpn_filters_choose((uint32_t)len, data);                   // 使用过滤器根据数据包内容选择特定隧道（基于pcap过滤规则）
    if (rtun) {
        /* High priority buffer, not reorderd when a filter applies */
        sbuf = rtun->hpsbuf;                // 使用高优先级缓冲区，过滤器匹配的数据包不参与重排序，直接发送
    }
#endif

    // 如果没有过滤器匹配或未启用过滤器功能
    if (!rtun) {
        rtun = mlvpn_rtun_choose();         // 使用默认隧道选择算法（加权轮询WRR），根据带宽权重和链路状态选择
        /* Not connected to anyone. read and discard packet. */
        // 没有可用的隧道连接
        if (! rtun) 
            return len;
        sbuf = rtun->sbuf;                  // 使用普通优先级发送缓冲区，数据包可能参与重排序
    }

    // 检查选中的发送缓冲区是否已满
    if (mlvpn_cb_is_full(sbuf))
        log_warnx("tuntap", "%s buffer: overflow", rtun->name);

    /* Ask for a free buffer */
    pkt = mlvpn_pktbuffer_write(sbuf);      // 从环形缓冲区获取一个可写的数据包槽位
    pkt->len = len;
    /* TODO: INEFFICIENT COPY */
    memcpy(pkt->data, data, pkt->len);

    // 如果写事件监听器未激活且缓冲区不为空
    if (!ev_is_active(&rtun->io_write) && !mlvpn_cb_is_empty(sbuf)) {
        ev_io_start(EV_DEFAULT_UC, &rtun->io_write);    // 启动libev写事件监听器，当socket可写时触发数据发送
    }
    return pkt->len;
}
