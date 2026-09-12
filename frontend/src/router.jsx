import { Outlet, Link, createRootRoute, createRoute, createRouter } from '@tanstack/react-router'

import Home from './pages/Home.jsx'
import Login from './pages/Login.jsx'
import Instrument from './pages/Instrument.jsx'
import DataExplore from './pages/DataExplore.jsx'

const rootRoute = createRootRoute({
  component: () => (
    <>
      <nav>
        <Link to="/">Home</Link>
        <Link to="/instrument">Instrument</Link>
        <Link to="/data-explore">Data Explore</Link>
        <Link to="/login">Login</Link>
      </nav>
      <Outlet />
    </>
  ),
})

const homeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: Home,
})

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: Login,
})

const instrumentRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/instrument',
  component: Instrument,
})

const dataExploreRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/data-explore',
  component: DataExplore,
})

const routeTree = rootRoute.addChildren([homeRoute, loginRoute, instrumentRoute, dataExploreRoute])

export const router = createRouter({ routeTree })
