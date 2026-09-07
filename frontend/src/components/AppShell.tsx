import { Activity, BellRing, Bot, Boxes, Braces, ChevronLeft, Database, FileText, Fingerprint, GitBranch, HardDrive, LayoutDashboard, Menu, Network, Radar, Search, ServerCog, ShieldCheck, X } from 'lucide-react'
import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useApi } from '../hooks/useApi'

const navigation = [
  ['安全态势总览','/',LayoutDashboard], ['攻击事件中心','/incidents',BellRing], ['攻击链溯源','/chains',GitBranch],
  ['安全知识图谱','/graph',Boxes], ['主机行为分析','/hosts',HardDrive], ['网络流量分析','/network',Network],
  ['日志与安全事件','/events',Braces], ['Agent 调查中心','/agents',Bot], ['ATT&CK 分析','/attack',ShieldCheck],
  ['威胁归因','/attribution',Fingerprint], ['数据源与资产','/sources',ServerCog], ['数据集实验','/datasets',Database], ['报告中心','/reports',FileText],
] as const

export function AppShell() {
  const [open, setOpen] = useState(false)
  const { data: health, error: healthError } = useApi<{status:string;mode:'live'|'replay'|'snapshot'}>('/api/system/health')
  return <div className="app-shell">
    <button className="mobile-menu" aria-label="打开导航" onClick={() => setOpen(true)}><Menu /></button>
    <aside className={`sidebar ${open ? 'open' : ''}`}>
      <div className="brand"><span className="brand-mark"><Radar size={20} /></span><div><strong>TraceGuard</strong><small>证据驱动溯源</small></div><button aria-label="关闭导航" className="close-nav" onClick={() => setOpen(false)}><X /></button></div>
      <nav aria-label="主要导航">{navigation.map(([label,to,Icon]) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setOpen(false)}><Icon size={17} /><span>{label}</span></NavLink>)}</nav>
      <div className="sidebar-foot"><span className={`status-dot ${healthError ? 'offline' : ''}`} />{healthError ? '分析节点不可用' : health ? '本地分析节点在线' : '正在检查分析节点'}<small>Schema 1.0 · ATT&CK 19.2</small></div>
    </aside>
    {open && <button className="scrim" aria-label="关闭导航" onClick={() => setOpen(false)} />}
    <main>
      <header className="topbar"><div className="case-context"><Activity size={16} /><span>运行模式</span><strong>{healthError ? 'OFFLINE' : health?.mode?.toUpperCase() ?? 'CHECKING'}</strong><span className="divider" />{healthError ? '无法读取分析窗口' : '当前窗口 · 全部已接入数据'}</div><button className="search-button"><Search size={16} />搜索事件、实体或证据 <kbd>⌘ K</kbd></button></header>
      <div className="content"><Outlet /></div>
    </main>
  </div>
}
