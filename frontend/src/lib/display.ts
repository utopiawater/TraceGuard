export const stageName: Record<string, string> = {
  initial_access: '初始访问',
  execution: '执行',
  persistence: '持久化',
  privilege_escalation: '权限提升',
  credential_access: '凭证访问',
  discovery: '发现',
  lateral_movement: '横向移动',
  collection: '收集',
  command_and_control: '命令与控制',
  exfiltration: '外传',
}

export const chainStatusName: Record<string, string> = {
  candidate: '候选链',
  confirmed: '已确认',
  dismissed: '已排除',
}

export const taskStatusName: Record<string, string> = {
  queued: '等待',
  running: '运行中',
  succeeded: '完成',
  partial: '部分完成',
  failed: '失败',
  cancelled: '已取消',
  denied: '已拒绝',
}

export const attributionStatusName: Record<string, string> = {
  candidate_analysis: '候选相似性分析',
  unable_to_attribute: '证据不足，暂不归因',
}

export const executionModeName: Record<string, string> = {
  real_llm: '真实 LLM',
  deterministic_fallback: '确定性降级',
  pending: '等待运行',
}

export const sourceStatusName: Record<string, string> = {
  ingested: '已接入',
  no_events: '无事件',
  delayed: '延迟',
  stale: '延迟',
  unhealthy: '异常',
  error: '异常',
  failed: '异常',
}

export const sourceDisplayName: Record<string, string> = {
  windows_security: 'Windows Security',
  sysmon: 'Sysmon',
  zeek: 'Zeek',
  wazuh: 'Wazuh',
  auditd: 'Auditd',
  dataset: 'Dataset',
}

export function pct(value: number | null | undefined, digits = 0) {
  return value == null ? 'N/A' : `${(value * 100).toFixed(digits)}%`
}
