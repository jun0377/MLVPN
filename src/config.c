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

#include "includes.h"
#include "mlvpn.h"
#include "configlib.h"
#include "tool.h"
#include "crypto.h"
#include "tuntap_generic.h"

extern char *status_command;
extern struct mlvpn_options_s mlvpn_options;
extern struct mlvpn_filters_s mlvpn_filters;
extern struct tuntap_s tuntap;
extern struct mlvpn_reorder_buffer *reorder_buffer;

/* Config file reading / re-read.
 * config_file_fd: fd opened in priv_open_config
 * first_time: set to 0 for re-read, or 1 for initial configuration
 */

/*
*   MLVPN配置解析
*/
int
mlvpn_config(int config_file_fd, int first_time)
{
    config_t *config, *work;                                        // config指向配置链表头，work用于遍历配置项
    mlvpn_tunnel_t *tmptun;                                         // 临时隧道指针，用于遍历现有隧道
    char *tmp = NULL;                                               // 临时字符串指针，用于存储配置值
    char *mode = NULL;                                              // 运行模式字符串（server/client）
    char *lastSection = NULL;                                       // 上一个配置段名称，用于跟踪当前处理的配置段
    char *tundevname = NULL;                                        // TUN/TAP设备名称
    char *password = NULL;                                          // 加密密码
    uint32_t tun_mtu = 0;                                           // TUN设备MTU值

    uint32_t default_loss_tolerence = 100;                          // 默认丢包容忍度（百分比）
    uint32_t default_latency_tolerence = 1000;                      // 默认延迟容忍度（百分比）
    uint32_t default_timeout = 60;                                  // 默认超时时间（秒）
    uint32_t default_server_mode = 0; /* 0 => client */             // 默认客户端模式（0=客户端，1=服务端）
    uint32_t cleartext_data = 0;                                    // 是否使用明文传输数据
    uint32_t fallback_only = 0;                                     // 是否仅作为备用隧道
    uint32_t reorder_buffer_size = 0;                               // 重排序缓冲区大小

    mlvpn_options.fallback_available = 0;                           // 重置备用隧道可用标志

    // 重置所有接口的BPF过滤器
#ifdef HAVE_FILTERS
    struct bpf_program filter;
    pcap_t *pcap_dead_p = pcap_open_dead(DLT_RAW, DEFAULT_MTU);
    memset(&mlvpn_filters, 0, sizeof(mlvpn_filters));
#endif

    work = config = _conf_parseConfig(config_file_fd);              // 解析配置文件，返回配置链表
    if (! config)
        goto error;

    // 遍历所有配置项
    while (work)
    {
        if ((work->section != NULL) && !mystr_eq(work->section, lastSection))
        {
            // 更新当前配置段名称
            lastSection = work->section;
            
            // 处理[general]配置段
            if (mystr_eq(lastSection, "general"))
            {
                // 以下设置只能在启动时设置
                if (first_time)
                {
                    // 从配置中读取状态命令脚本路径
                    _conf_set_str_from_conf(
                        config, lastSection, "statuscommand", &status_command, NULL,
                        NULL, 0);

                    // 从配置中读取接口名称，默认为"mlvpn0"
                    _conf_set_str_from_conf(
                        config, lastSection, "interface_name", &tundevname, "mlvpn0",
                        NULL, 0);
                    if (tundevname) {
                        strlcpy(tuntap.devname, tundevname, sizeof(tuntap.devname));
                        free(tundevname);
                    }

                     // 从配置中读取tuntap类型，默认为"tun"
                    _conf_set_str_from_conf(
                        config, lastSection, "tuntap", &tmp, "tun", NULL, 0);
                    if (tmp) {
                        if (mystr_eq(tmp, "tun"))
                            tuntap.type = MLVPN_TUNTAPMODE_TUN;
                        else
                            tuntap.type = MLVPN_TUNTAPMODE_TAP;
                        free(tmp);
                    }

                    // 控制接口配置
                    _conf_set_str_from_conf(
                        config, lastSection, "control_unix_path", &tmp, NULL,
                        NULL, 0);
                    if (tmp) {
                        strlcpy(mlvpn_options.control_unix_path, tmp,
                            sizeof(mlvpn_options.control_unix_path));
                        free(tmp);
                    }

                    // 从配置中读取控制接口绑定主机
                    _conf_set_str_from_conf(
                        config, lastSection, "control_bind_host", &tmp, NULL,
                        NULL, 0);
                    if (tmp) {
                        strlcpy(mlvpn_options.control_bind_host, tmp,
                            sizeof(mlvpn_options.control_bind_host));
                        free(tmp);
                    }

                    // 从配置中读取控制接口绑定端口
                    _conf_set_str_from_conf(
                        config, lastSection, "control_bind_port", &tmp, NULL,
                        NULL, 0);
                    if (tmp) {
                        strlcpy(mlvpn_options.control_bind_port, tmp,
                            sizeof(mlvpn_options.control_bind_port));
                        free(tmp);
                    }
                }
                /* This is important to be parsed every time because
                 * it's used later in the configuration parsing
                 */

                // 从配置中读取运行模式，必须指定
                _conf_set_str_from_conf(
                    config, lastSection, "mode", &mode, NULL,
                    "Operation mode is mandatory.", 1);
                if (mystr_eq(mode, "server"))
                    default_server_mode = 1;
                if (mode)
                    free(mode);
                
                // 从配置中读取加密密码，必须指定
                _conf_set_str_from_conf(
                    config, lastSection, "password", &password, NULL,
                    "Password is mandatory.", 2);
                if (password) {
                    log_info("config", "new password set");
                    crypto_set_password(password, strlen(password));
                    memset(password, 0, strlen(password));
                    free(password);
                }

                // 从配置中读取明文数据传输标志，默认为0
                _conf_set_uint_from_conf(
                    config, lastSection, "cleartext_data", &cleartext_data, 0,
                    NULL, 0);
                mlvpn_options.cleartext_data = cleartext_data;

                // 从配置中读取默认超时时间，默认60秒
                _conf_set_uint_from_conf(
                    config, lastSection, "timeout", &default_timeout, 60,
                    NULL, 0);
                if (default_timeout < 2) {
                    log_warnx("config", "timeout capped to 2 seconds");
                    default_timeout = 2;
                }

                // 从配置中读取重排序缓冲区大小，默认为0
                _conf_set_uint_from_conf(
                    config, lastSection, "reorder_buffer_size",
                    &reorder_buffer_size,
                    0, NULL, 0);

                // 如果重排序缓冲区大小发生变化
                if (reorder_buffer_size != mlvpn_options.reorder_buffer_size) {
                    log_info("config",
                        "reorder_buffer_size changed from %d to %d",
                        mlvpn_options.reorder_buffer_size,
                        reorder_buffer_size);
                    if (reorder_buffer_size != 0 &&
                            mlvpn_options.reorder_buffer_size != 0) {
                        mlvpn_reorder_free(reorder_buffer); // 释放旧的重排序缓冲区
                        reorder_buffer = NULL;
                    }
                    mlvpn_options.reorder_buffer_size = reorder_buffer_size;
                    if (mlvpn_options.reorder_buffer_size > 0) {
                        if (reorder_buffer) {
                            mlvpn_reorder_free(reorder_buffer);
                        }

                        // 创建新的重排序缓冲区
                        reorder_buffer = mlvpn_reorder_create(
                            mlvpn_options.reorder_buffer_size);
                        if (reorder_buffer == NULL) {
                            fatal("config", "reorder_buffer allocation failed");
                        }
                    }
                }

                // 从配置中读取默认丢包容忍度，默认100%
                _conf_set_uint_from_conf(
                    config, lastSection, "loss_tolerence",
                    &default_loss_tolerence, 100,  NULL, 0);
                if (default_loss_tolerence > 100) {
                    log_warnx("config", "loss_tolerence is capped to 100 %%");
                    default_loss_tolerence = 100;
                }

                // 从配置中读取默认延迟容忍度，默认1000%
                _conf_set_uint_from_conf(
                        config, lastSection, "latency_tolerence",
                        &default_latency_tolerence, 1000,  NULL, 0);
                if (default_latency_tolerence > 1000) {
                    log_warnx("config", "latency_tolerence is capped to 1000 %%");
                    default_latency_tolerence = 1000;
                }

                // 隧道网络配置
                // 从配置中读取IPv4地址
                _conf_set_str_from_conf(
                    config, lastSection, "ip4", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip4, tmp, sizeof(mlvpn_options.ip4));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip4_gateway, 0,
                        sizeof(mlvpn_options.ip4_gateway));
                }

                // 从配置中读取IPv6地址
                _conf_set_str_from_conf(
                    config, lastSection, "ip6", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip6, tmp, sizeof(mlvpn_options.ip6));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip4_gateway, 0,
                        sizeof(mlvpn_options.ip4_gateway));
                }

                // 从配置中读取IPv4网关地址
                _conf_set_str_from_conf(
                    config, lastSection, "ip4_gateway", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip4_gateway, tmp,
                        sizeof(mlvpn_options.ip4_gateway));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip4_gateway, 0,
                        sizeof(mlvpn_options.ip4_gateway));
                }

                // 从配置中读取IPv6网关地址
                _conf_set_str_from_conf(
                    config, lastSection, "ip6_gateway", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip6_gateway, tmp,
                        sizeof(mlvpn_options.ip6_gateway));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip6_gateway, 0,
                        sizeof(mlvpn_options.ip6_gateway));
                }

                // 从配置中读取IPv4路由表
                _conf_set_str_from_conf(
                    config, lastSection, "ip4_routes", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip4_routes, tmp,
                        sizeof(mlvpn_options.ip4_routes));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip4_routes, 0,
                        sizeof(mlvpn_options.ip4_routes));
                }

                // 从配置中读取IPv6路由表
                _conf_set_str_from_conf(
                    config, lastSection, "ip6_routes", &tmp, NULL, NULL, 0);
                if (tmp) {
                    strlcpy(mlvpn_options.ip6_routes, tmp,
                        sizeof(mlvpn_options.ip6_routes));
                    free(tmp);
                } else {
                    memset(mlvpn_options.ip6_routes, 0,
                        sizeof(mlvpn_options.ip6_routes));
                }

                // 从配置中读取MTU值，默认1432字节
                _conf_set_uint_from_conf(
                    config, lastSection, "mtu", &tun_mtu, 1432, NULL, 0);
                if (tun_mtu != 0) {
                    mlvpn_options.mtu = tun_mtu;
                }
            } 
            // 如果不是"filters"配置段，则处理隧道配置段
            else if (strncmp(lastSection, "filters", 7) != 0) {
                char *bindaddr;                 // 本地绑定地址
                char *bindport;                 // 本地绑定端口
                uint32_t bindfib = 0;           // 绑定的路由表ID
                char *dstaddr;                  // 远程目标地址
                char *dstport;                  // 远程目标端口
                uint32_t bwlimit = 0;           // 带宽限制
                uint32_t timeout = 30;          // 隧道超时时间
                uint32_t loss_tolerence;        // 隧道丢包容忍度
                uint32_t latency_tolerence;     // 隧道延迟容忍度
                int create_tunnel = 1;          // 是否需要创建新隧道的标志

                // 服务器模式
                if (default_server_mode)
                {
                    // 从配置中读取绑定主机地址（可选）
                    _conf_set_str_from_conf(
                        config, lastSection, "bindhost", &bindaddr, NULL,
                        NULL, 0);

                    // 从配置中读取绑定端口（服务器模式必须）
                    _conf_set_str_from_conf(
                        config, lastSection, "bindport", &bindport, NULL,
                        "bind port is mandatory in server mode.\n", 1);

                    // 从配置中读取绑定路由表ID，默认为0
                    _conf_set_uint_from_conf(
                        config, lastSection, "bindfib", &bindfib, 0,
                        NULL, 0);

                    // 从配置中读取远程主机地址（可选）
                    _conf_set_str_from_conf(
                        config, lastSection, "remotehost", &dstaddr, NULL,
                        NULL, 0);

                    // 从配置中读取远程端口（可选）
                    _conf_set_str_from_conf(
                        config, lastSection, "remoteport", &dstport, NULL,
                        NULL, 0);
                } 
                // 客户端模式
                else {
                    // 从配置中读取绑定主机地址（可选）
                    _conf_set_str_from_conf(
                        config, lastSection, "bindhost", &bindaddr, NULL,
                        NULL, 0);
                    // 从配置中读取绑定端口（可选）
                    _conf_set_str_from_conf(
                        config, lastSection, "bindport", &bindport, NULL,
                        NULL, 0);
                    // 从配置中读取绑定路由表ID，默认为0
                     _conf_set_uint_from_conf(
                        config, lastSection, "bindfib", &bindfib, 0,
                        NULL, 0);
                    // 从配置中读取远程主机地址（客户端模式必须）
                    _conf_set_str_from_conf(
                        config, lastSection, "remotehost", &dstaddr, NULL,
                        "No remote address specified.\n", 1);
                    // 从配置中读取远程端口（客户端模式必须）
                    _conf_set_str_from_conf(
                        config, lastSection, "remoteport", &dstport, NULL,
                        "No remote port specified.\n", 1);
                }
                // 从配置中读取上传带宽限制，默认为0（无限制）
                _conf_set_uint_from_conf(
                    config, lastSection, "bandwidth_upload", &bwlimit, 0,
                    NULL, 0);
                // 从配置中读取隧道超时时间，使用默认值
                _conf_set_uint_from_conf(
                    config, lastSection, "timeout", &timeout, default_timeout,
                    NULL, 0);
                if (timeout < 2) {
                    log_warnx("config", "timeout capped to 2 seconds");
                    timeout = 2;
                }
                // 从配置中读取隧道丢包容忍度，使用默认值
                _conf_set_uint_from_conf(
                    config, lastSection, "loss_tolerence", &loss_tolerence,
                    default_loss_tolerence, NULL, 0);
                if (loss_tolerence > 100) {
                    log_warnx("config", "loss_tolerence is capped to 100 %%");
                    loss_tolerence = 100;
                }
                // 从配置中读取隧道延迟容忍度，使用默认值
                _conf_set_uint_from_conf(
                        config, lastSection, "latency_tolerence", &latency_tolerence,
                        default_latency_tolerence, NULL, 0);
                if (latency_tolerence > 1000) {
                    log_warnx("config", "latency_tolerence is capped to 1000 %%");
                    latency_tolerence = 1000;
                }
                // 从配置中读取是否仅作为备用隧道，默认为0
                _conf_set_uint_from_conf(
                    config, lastSection, "fallback_only", &fallback_only, 0,
                    NULL, 0);
                if (fallback_only) {
                    mlvpn_options.fallback_available = 1;
                }
                // 遍历现有隧道列表
                LIST_FOREACH(tmptun, &rtuns, entries)
                {
                    // 如果找到同名隧道，更新配置
                    if (mystr_eq(lastSection, tmptun->name))
                    {
                        log_info("config",
                            "%s restart for configuration reload",
                              tmptun->name);
                        if ((! mystr_eq(tmptun->bindaddr, bindaddr)) ||
                                (! mystr_eq(tmptun->bindport, bindport)) ||
                                (tmptun->bindfib != bindfib) ||
                                (! mystr_eq(tmptun->destaddr, dstaddr)) ||
                                (! mystr_eq(tmptun->destport, dstport))) {
                            mlvpn_rtun_status_down(tmptun);
                        }

                        if (bindaddr) {
                            strlcpy(tmptun->bindaddr, bindaddr, sizeof(tmptun->bindaddr));
                        }
                        if (bindport) {
                            strlcpy(tmptun->bindport, bindport, sizeof(tmptun->bindport));
                        }
                        if (tmptun->bindfib != bindfib) {
                            tmptun->bindfib = bindfib;
                        }
                        if (dstaddr) {
                            strlcpy(tmptun->destaddr, dstaddr, sizeof(tmptun->destaddr));
                        }
                        if (dstport) {
                            strlcpy(tmptun->destport, dstport, sizeof(tmptun->destport));
                        }
                        if (tmptun->fallback_only != fallback_only)
                        {
                            log_info("config", "%s fallback_only changed from %d to %d",
                                tmptun->name, tmptun->fallback_only, fallback_only);
                            tmptun->fallback_only = fallback_only;
                        }
                        if (tmptun->bandwidth != bwlimit)
                        {
                        log_info("config", "%s bandwidth changed from %d to %d",
                                tmptun->name, tmptun->bandwidth, bwlimit);
                            tmptun->bandwidth = bwlimit;
                        }
                        if (tmptun->loss_tolerence != loss_tolerence)
                        {
                            log_info("config", "%s loss tolerence changed from %d%% to %d%%",
                                tmptun->name, tmptun->loss_tolerence, loss_tolerence);
                            tmptun->loss_tolerence = loss_tolerence;
                        }
                        if (tmptun->latency_tolerence != latency_tolerence)
                        {
                            log_info("config", "%s latency tolerence changed from %d%% to %d%%",
                                     tmptun->name, tmptun->latency_tolerence, latency_tolerence);
                            tmptun->latency_tolerence = latency_tolerence;
                        }
                        create_tunnel = 0;      // 标记不需要创建新隧道
                        break; /* Very important ! */
                    }
                }
                
                // 如果需要创建新隧道
                if (create_tunnel)
                {
                    log_info("config", "%s tunnel added", lastSection);
                    // 创建新隧道
                    mlvpn_rtun_new(
                        lastSection, bindaddr, bindport, bindfib, dstaddr, dstport,
                        default_server_mode, timeout, fallback_only,
                        bwlimit, loss_tolerence, latency_tolerence);
                }
                if (bindaddr)
                    free(bindaddr);
                if (bindport)
                    free(bindport);
                if (dstaddr)
                    free(dstaddr);
                if (dstport)
                    free(dstport);
            }
        } else if (lastSection == NULL)
            lastSection = work->section;
        work = work->next;
    }

    // 删除配置中不存在的旧隧道
    // 如果不是首次加载
    if (! first_time)
    {
         // 遍历现有隧道列表
        LIST_FOREACH(tmptun, &rtuns, entries)
        {
            int found_in_config = 0;    // 在配置中找到的标志

            work = config;              // 重新遍历配置
            while (work)
            {
                // 如果配置项有效 且有配置段名称 且配置段名称与隧道名称匹配
                if (work->conf && work->section &&
                        mystr_eq(work->section, tmptun->name))
                {
                    found_in_config = 1;    // 标记在配置中找到
                    break;
                }
                work = work->next;
            }

            // 如果在配置中未找到该隧道
            if (! found_in_config)
            {
                log_info("config", "%s tunnel removed", tmptun->name);
                mlvpn_rtun_drop(tmptun);    // 删除隧道
            }
        }
    }

    // 如果启用了过滤器功能
#ifdef HAVE_FILTERS
    work = config;                  // 重新遍历配置
    int found_in_config = 0;        // 在配置中找到的标志

    // 遍历所有配置项
    while (work)
    {   
        // 如果配置段名称不为空 且 是"filters"配置段 
        if (work->section != NULL &&
                strncmp(work->section, "filters", 7) == 0) {
            // 清零过滤器结构体
            memset(&filter, 0, sizeof(filter));
            // 编译BPF过滤器
            if (pcap_compile(pcap_dead_p, &filter, work->conf->val,
                    1, PCAP_NETMASK_UNKNOWN) != 0) {
                log_warnx("config", "invalid filter %s = %s: %s",
                    work->conf->var, work->conf->val, pcap_geterr(pcap_dead_p));
            } else {
                // 重置找到标志
                found_in_config = 0;
                // 遍历隧道列表
                LIST_FOREACH(tmptun, &rtuns, entries) {
                    // 如果过滤器变量名与隧道名匹配
                    if (strcmp(work->conf->var, tmptun->name) == 0) {
                        // 添加过滤器到隧道
                        if (mlvpn_filters_add(&filter, tmptun) != 0) {
                            log_warnx("config", "%s filter %s error: too many filters",
                                tmptun->name, work->conf->val);
                        } else {
                            // 标记找到匹配隧道
                            log_debug("config", "%s added filter: %s",
                                tmptun->name, work->conf->val);
                            found_in_config = 1;
                            break;
                        }
                    }
                }
                if (!found_in_config) {
                    log_warnx("config", "(filters) %s interface not found",
                        work->conf->var);
                }
            }
        }
        work = work->next;
    }
#endif

    //_conf_printConfig(config);
    _conf_freeConfig(config);                   // 释放配置内存
#ifdef HAVE_FILTERS
    pcap_close(pcap_dead_p);                    // 关闭pcap
#endif

    // 如果是首次加载且指定了状态命令
    if (first_time && status_command)
        priv_init_script(status_command);
    return 0;
error:
    log_warnx("config", "parse error");
    return 1;
}
