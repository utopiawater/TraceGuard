import { Activity, BellRing, Bot, Boxes, Braces, ChevronDown, Database, FileText, Fingerprint, GitBranch, HardDrive, LayoutDashboard, Menu, Network, Radar, Search, ServerCog, ShieldCheck, UploadCloud, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { FormEvent, useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { useApi } from '../hooks/useApi'

type NavItem = {
  label: string
  to: string
  icon: LucideIcon
  end?: boolean
}

type NavSection = NavItem | {
  key: string
  label: string
  icon: LucideIcon
  children: NavItem[]
}

const navigation: NavSection[] = [
  { label: '安全态势总览', to: '/', icon: LayoutDashboard, end: true },
  {
    key: 'investigation',
    label: '攻击调查',
    icon: BellRing,
    children: [
      { label: '攻击事件中心', to: '/incidents', icon: BellRing },
      { label: '攻击链溯源', to: '/chains', icon: GitBranch },
      { label: 'Agent 调查中心', to: '/agents', icon: Bot },
    ],
  },
  {
    key: 'analytics',
    label: '数据分析',
    icon: Braces,
    children: [
      { label: '日志与安全事件', to: '/events', icon: Braces },
      { label: '主机行为分析', to: '/hosts', icon: HardDrive },
      { label: '网络流量分析', to: '/network', icon: Network },
    ],
  },
  {
    key: 'threat',
    label: '威胁分析',
    icon: ShieldCheck,
    children: [
      { label: '安全知识图谱', to: '/graph', icon: Boxes },
      { label: 'ATT&CK 分析', to: '/attack', icon: ShieldCheck },
      { label: '威胁归因', to: '/attribution', icon: Fingerprint },
    ],
  },
  {
    key: 'data',
    label: '数据管理',
    icon: Database,
    children: [
      { label: '数据源与资产', to: '/sources', icon: ServerCog },
      { label: '在线分析', to: '/analysis', icon: UploadCloud },
      { label: '数据集实验', to: '/datasets', icon: Database },
    ],
  },
  { label: '报告中心', to: '/reports', icon: FileText },
]

function isGroup(section: NavSection): section is Extract<NavSection, { children: NavItem[] }> {
  return 'children' in section
}

function isRouteActive(pathname: string, item: NavItem) {
  return item.end ? pathname === item.to : pathname === item.to || pathname.startsWith(`${item.to}/`)
}

function activeGroupsFor(pathname: string) {
  return new Set(
    navigation
      .filter(isGroup)
      .filter(section => section.children.some(item => isRouteActive(pathname, item)))
      .map(section => section.key),
  )
}

export function AppShell() {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [searchText, setSearchText] = useState(params.get('q') ?? '')
  const [openGroups, setOpenGroups] = useState(() => activeGroupsFor(location.pathname))
  const { data: health, error: healthError } = useApi<{status:string;mode:'live'|'replay'|'snapshot'}>('/api/system/health')

  useEffect(() => {
    const activeGroups = activeGroupsFor(location.pathname)
    setOpenGroups(previous => new Set([...previous, ...activeGroups]))
  }, [location.pathname])

  useEffect(() => {
    if (location.pathname === '/search') setSearchText(params.get('q') ?? '')
  }, [location.pathname, params])

  const toggleGroup = (key: string) => {
    setOpenGroups(previous => {
      const next = new Set(previous)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const submitSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const query = searchText.trim()
    if (!query) return
    navigate(`/search?q=${encodeURIComponent(query)}`)
  }

  return <div className="app-shell">
    <button className="mobile-menu" aria-label="打开导航" onClick={() => setOpen(true)}><Menu /></button>
    <aside className={`sidebar ${open ? 'open' : ''}`}>
      <div className="brand"><span className="brand-mark"><Radar size={20} /></span><div><strong>TraceGuard</strong><small>证据驱动溯源</small></div><button aria-label="关闭导航" className="close-nav" onClick={() => setOpen(false)}><X /></button></div>
      <nav className="sidebar-nav" aria-label="主要导航">
        {navigation.map(section => {
          if (!isGroup(section)) {
            const Icon = section.icon
            return <NavLink key={section.to} className="nav-root" to={section.to} end={section.end} onClick={() => setOpen(false)}><Icon size={17} /><span>{section.label}</span></NavLink>
          }

          const Icon = section.icon
          const isOpen = openGroups.has(section.key)
          const isActive = section.children.some(item => isRouteActive(location.pathname, item))
          return <div key={section.key} className={`nav-group ${isOpen ? 'open' : ''} ${isActive ? 'active' : ''}`}>
            <button type="button" className="nav-group-trigger" aria-expanded={isOpen} onClick={() => toggleGroup(section.key)}>
              <Icon size={17} />
              <span>{section.label}</span>
              <ChevronDown className="nav-chevron" size={15} />
            </button>
            <div className="nav-group-children">
              {section.children.map(item => {
                const ChildIcon = item.icon
                return <NavLink key={item.to} className="nav-child" to={item.to} onClick={() => setOpen(false)}><ChildIcon size={15} /><span>{item.label}</span></NavLink>
              })}
            </div>
          </div>
        })}
      </nav>
      <div className="sidebar-foot"><span className={`status-dot ${healthError ? 'offline' : ''}`} />{healthError ? '分析节点不可用' : health ? '本地分析节点在线' : '正在检查分析节点'}<small>Schema 1.0 · ATT&CK 19.2</small></div>
    </aside>
    {open && <button className="scrim" aria-label="关闭导航" onClick={() => setOpen(false)} />}
    <main>
      <header className="topbar"><div className="case-context"><Activity size={16} /><span>运行模式</span><strong>{healthError ? '离线' : health?.mode === 'live' ? '实时' : health?.mode === 'snapshot' ? '快照' : '回放'}</strong><span className="divider" />{healthError ? '无法读取分析窗口' : '当前窗口 · 全部已接入数据'}</div><form className="search-button global-search" onSubmit={submitSearch}><Search size={16} /><input value={searchText} onChange={event=>setSearchText(event.target.value)} placeholder="搜索事件、实体、证据或攻击链" aria-label="全局搜索" /><kbd>Enter</kbd></form></header>
      <div className="content"><Outlet /></div>
    </main>
  </div>
}
