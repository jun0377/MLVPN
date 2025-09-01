#ifndef MLVPN_TIMESTAMP_H
#define MLVPN_TIMESTAMP_H

#include <stdint.h>
#include <ev.h>


// 将libev时间戳转换为毫秒时间戳
uint64_t
mlvpn_timestamp64(ev_tstamp now);

// 将64位时间戳压缩为16位时间戳
// MLVPN主要关心的是 数据包之间的时间差 ，而不是绝对时间
// 16位时间戳可以表示0-65535的范围，足以处理网络延迟和抖动的测量
// 通过 mlvpn_timestamp16_diff 函数可以正确计算时间差，即使发生环绕
uint16_t
mlvpn_timestamp16(uint64_t now);

// 计算两个16位时间戳之间的差值，处理环绕情况
uint16_t
mlvpn_timestamp16_diff(uint16_t tsnew, uint16_t tsold);

#endif