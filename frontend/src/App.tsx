import { lazy, Suspense, type ReactNode } from 'react'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { AttackPage, DatasetsPage, EventsPage, GraphPage, HostsPage, IncidentsPage, NetworkPage, SourcesPage } from './pages/Pages'
import { AgentsPage } from './pages/AgentsPage'
import { AttributionPage } from './pages/AttributionPage'
import { ReportsPage } from './pages/ReportsPage'

const DashboardPage = lazy(() => import('./pages/DashboardPage').then(module => ({ default: module.DashboardPage })))
const ChainPage = lazy(() => import('./pages/ChainPage').then(module => ({ default: module.ChainPage })))
const pending = <div className="skeleton-hero" aria-label="正在加载页面" />
const lazyPage = (page: ReactNode) => <Suspense fallback={pending}>{page}</Suspense>

const router=createBrowserRouter([{path:'/',element:<AppShell/>,children:[
  {index:true,element:lazyPage(<DashboardPage/>)},{path:'incidents',element:<IncidentsPage/>},{path:'chains',element:lazyPage(<ChainPage/>)},
  {path:'graph',element:<GraphPage/>},{path:'hosts',element:<HostsPage/>},{path:'network',element:<NetworkPage/>},
  {path:'events',element:<EventsPage/>},{path:'agents',element:<AgentsPage/>},{path:'attack',element:<AttackPage/>},
  {path:'attribution',element:<AttributionPage/>},{path:'sources',element:<SourcesPage/>},{path:'datasets',element:<DatasetsPage/>},{path:'reports',element:<ReportsPage/>},
]}])

export default function App(){return <RouterProvider router={router}/>}
