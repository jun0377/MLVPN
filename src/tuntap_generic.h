#ifndef MLVPN_TUNTAP_GENERIC_H
#define MLVPN_TUNTAP_GENERIC_H

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ev.h>

#include "buffer.h"
#include "privsep.h"
#include "mlvpn.h"

enum tuntap_type {
    MLVPN_TUNTAPMODE_TUN,       // TUN
    MLVPN_TUNTAPMODE_TAP        // TAP
};

struct tuntap_s
{
    int fd;
    int maxmtu;                     // 最大传输单元大小，限制通过此设备传输的数据包最大字节数（通常为1472字节，考虑MLVPN协议头开销）
    char devname[MLVPN_IFNAMSIZ];
    enum tuntap_type type;
    circular_buffer_t *sbuf;        // 发送缓冲区
    ev_io io_read;                  // libev读事件监听器，当TUN/TAP设备有数据可读时触发，调用tuntap_io_event处理函数
    ev_io io_write;                 // libev写事件监听器，当TUN/TAP设备可写且发送缓冲区有数据时触发，执行数据包写入操作
};

int mlvpn_tuntap_alloc(struct tuntap_s *tuntap);
int mlvpn_tuntap_read(struct tuntap_s *tuntap);
int mlvpn_tuntap_write(struct tuntap_s *tuntap);
int mlvpn_tuntap_generic_read(u_char *data, uint32_t len);

#endif
