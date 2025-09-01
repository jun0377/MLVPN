#include "mlvpn.h"

/* Fairly big no ? */
#define MAX_TUNNELS 128

/**
 * 加权轮询（Weighted Round Robin）算法的核心数据结构
 * 用于管理MLVPN中多个隧道的负载均衡和流量分配
 * 
 * 设计目标：
 * - 根据隧道带宽权重智能分配流量
 * - 实现多链路聚合的负载均衡
 * - 支持最多128个并发隧道连接
 */
struct mlvpn_wrr {
    int len;                                // 当前可用隧道数量，0 ~ MAX_TUNNELS
    mlvpn_tunnel_t *tunnel[MAX_TUNNELS];    // 隧道指针数组：存储所有参与负载均衡的隧道对象
    double tunval[MAX_TUNNELS];             // 隧道权重值数组：存储每个隧道的当前权重
                                            // 权重值越小 = 该隧道被使用得越少 = 下次被选中概率越高
                                            // 初始值为0.0，选中后重置为 100.0/隧道配置权重
                                            // 每轮选择后所有隧道权重值递减1
};

static struct mlvpn_wrr wrr = {
    0,
    {NULL},
    {0}
};

static int wrr_min_index()
{
    double min = 100.0;
    int min_index = 0;
    int i;

    for(i = 0; i < wrr.len; i++)
    {
        if (wrr.tunval[i] < min)
        {
            min = wrr.tunval[i];
            min_index = i;
        }
    }
    return min_index;
}

/* initialize wrr system */
int mlvpn_rtun_wrr_reset(struct rtunhead *head, int use_fallbacks)
{
    mlvpn_tunnel_t *t;
    wrr.len = 0;
    LIST_FOREACH(t, head, entries)
    {
        // 跳过不匹配模式的隧道，即是否使用备份链路
        if (t->fallback_only != use_fallbacks) {
            continue;
        }
        /* Don't select "LOSSY" tunnels, except if we are in fallback mode */
        // 备用隧道只要认证通过（状态 ≥ AUTHOK）就可用,即使连接质量较差（LOSSY）也会被选中; 
        // 主隧道必须状态完全正常,不接受有损耗的连接
        if ((t->fallback_only && t->status >= MLVPN_AUTHOK) ||
            (t->status == MLVPN_AUTHOK))
        {
            if (wrr.len >= MAX_TUNNELS)
                fatalx("You have too many tunnels declared");
            wrr.tunnel[wrr.len] = t;        // 存储隧道指针
            wrr.tunval[wrr.len] = 0.0;      // 初始化虚拟权重值为0
            wrr.len++;                      // 增加隧道计数
        }
    }

    return 0;
}

/**
 * 加权轮询隧道选择算法
 * 功能：根据隧道权重（基于带宽）选择最合适的隧道进行数据传输
 * 返回值：选中的隧道指针，如果没有可用隧道则返回NULL
 * 
 * 前提：权重越小表示该隧道被使用得越少,下一轮选择时应当优先选择此隧道
 * 
 * 算法原理：
 * - 每个隧道有一个权重值（基于带宽配置）
 * - 选择当前权重值最小的隧道,注意是最小，不是最大
 * - 所有隧道权重递减，选中隧道权重重置
 * - 实现按带宽比例的流量分配
 * 
 * 选择策略：
 * - 最小权重优先 ：总是选择当前权重值最小的隧道
 * - 权重衰减 ：所有隧道权重每次都减1，防止权重无限增长
 * - 权重重置 ：选中的隧道权重重新计算，确保下次选择的公平性
 * 
 * 负载均衡效果 ：
 * - 假设有两个隧道：
 *      - 隧道A：配置权重=2，带宽=200Mbps
 *      - 隧道B：配置权重=1，带宽=100Mbps
*   经过多次选择后，隧道A会被选中约2倍于隧道B的次数，实现了按带宽比例的流量分配。
 */
mlvpn_tunnel_t *
mlvpn_rtun_wrr_choose()
{
    int i;
    int idx;

    if (wrr.len == 0)           // 检查是否有可用隧道
        return NULL;

    idx = wrr_min_index();      // 找到当前权重值最小的隧道索引，权重越小表示该隧道被使用得越少,应当优先选择此隧道
    if (idx < 0)
        fatalx("Programming error: wrr_min_index < 0!");

    // 遍历所有可用隧道，全局权重衰减，防止饥饿
    // 确保长时间未被选中的隧道权重值最终会降到最低，给低权重隧道创造被选中的机会
    for(i = 0; i < wrr.len; i++)
    {   
        if (wrr.tunval[i] > 0)
            wrr.tunval[i] -= 1;
    }

    // 重置选中隧道的权重值：100除以隧道配置权重
    // 配置权重越高的隧道重置值越小，下次被选中概率越高,因为优选选择权重最小的隧道
    wrr.tunval[idx] = (double) 100.0 / wrr.tunnel[idx]->weight;
    return wrr.tunnel[idx];
}
