export function PageHeader({ title, description, aside }: { title: string; description: string; aside?: React.ReactNode }) {
  return <header className="page-header"><div><h1>{title}</h1><p>{description}</p></div>{aside}</header>
}

