import { CircleOff, DatabaseZap, RotateCw } from 'lucide-react'

export function EmptyState({ title, detail, kind = 'empty' }: { title: string; detail: string; kind?: 'empty' | 'error' }) {
  const Icon = kind === 'error' ? DatabaseZap : CircleOff
  return <section className={`empty-state ${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
    <Icon size={22} aria-hidden="true" />
    <div><h2>{title}</h2><p>{detail}</p></div>
    {kind === 'error' && <button type="button" onClick={() => location.reload()}><RotateCw size={15} />重试</button>}
  </section>
}

