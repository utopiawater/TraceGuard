# Testbed

`topology.yaml` 是最终 9 节点逻辑拓扑与传感器覆盖契约。真实 8+ 节点靶场由团队同学在云平台搭建，本目录保留 TraceGuard 侧需要的角色、网段、传感器和 manifest 约束。

靶场脚本必须默认禁止公网攻击目标；攻击与 C2 软件只允许在隔离实验网络内运行。云平台导出的日志 bundle、Ground Truth manifest、截图和录像按 `docs/13_cloud_testbed_handoff.md` 对接，不改变主系统数据契约。
