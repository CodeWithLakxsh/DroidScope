/** Application shell: sidebar navigation, header and theme control. */

import { useEffect, useState, type ReactNode } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Binary,
  Code2,
  FileText,
  GitCompare,
  Globe,
  LayoutDashboard,
  Menu,
  Moon,
  Package,
  Settings as SettingsIcon,
  Smartphone,
  Sun,
  Upload,
  X,
} from 'lucide-react';
import { api } from '@/lib/api';
import { cn } from '@/lib/cn';
import { StatusBadge } from '@/components/ui';

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  end?: boolean;
}

const PRIMARY_NAV: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: <LayoutDashboard className="size-4" />, end: true },
  { to: '/upload', label: 'Upload APK', icon: <Upload className="size-4" /> },
  { to: '/applications', label: 'Applications', icon: <Package className="size-4" /> },
  { to: '/scans', label: 'Scans', icon: <Activity className="size-4" /> },
];

const ANALYSIS_NAV: NavItem[] = [
  { to: '/findings', label: 'Findings', icon: <AlertTriangle className="size-4" /> },
  { to: '/code', label: 'Code explorer', icon: <Code2 className="size-4" /> },
  { to: '/manifest', label: 'Manifest', icon: <FileText className="size-4" /> },
  { to: '/indicators', label: 'Network indicators', icon: <Globe className="size-4" /> },
  { to: '/binary', label: 'Binary analysis', icon: <Binary className="size-4" /> },
  { to: '/graphs', label: 'Visualisations', icon: <BarChart3 className="size-4" /> },
];

const TOOLS_NAV: NavItem[] = [
  { to: '/compare', label: 'Compare APKs', icon: <GitCompare className="size-4" /> },
  { to: '/dynamic', label: 'Dynamic analysis', icon: <Smartphone className="size-4" /> },
  { to: '/reports', label: 'Reports', icon: <FileText className="size-4" /> },
  { to: '/settings', label: 'Settings', icon: <SettingsIcon className="size-4" /> },
];

function useTheme() {
  const [dark, setDark] = useState(() =>
    typeof document !== 'undefined' ? document.documentElement.classList.contains('dark') : true,
  );

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
    try {
      localStorage.setItem('droidscope-theme', dark ? 'dark' : 'light');
    } catch {
      /* storage may be unavailable in a private window */
    }
  }, [dark]);

  return { dark, toggle: () => setDark((value) => !value) };
}

function NavSection({ title, items, onNavigate }: { title: string; items: NavItem[]; onNavigate?: () => void }) {
  return (
    <div className="mb-4">
      <h2 className="mb-1 px-3 text-[10px] font-semibold tracking-wider text-subtle uppercase">
        {title}
      </h2>
      <ul className="space-y-0.5">
        {items.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.end}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2.5 rounded-sm px-3 py-1.5 text-[13px] transition-colors duration-150',
                  isActive ? 'font-medium' : 'text-muted hover:text-[var(--text)]',
                )
              }
              style={({ isActive }) =>
                isActive
                  ? { backgroundColor: 'var(--surface-hover)', color: 'var(--accent)' }
                  : undefined
              }
            >
              <span aria-hidden="true" className="shrink-0">
                {item.icon}
              </span>
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Layout() {
  const { dark, toggle } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  // Close the drawer whenever the route changes on a small screen.
  useEffect(() => setMobileOpen(false), [location.pathname]);

  const health = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 30_000,
    retry: 1,
  });

  const close = () => setMobileOpen(false);

  return (
    <div className="flex h-full" style={{ backgroundColor: 'var(--surface-sunken)' }}>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-sm focus:px-3 focus:py-2"
        style={{ backgroundColor: 'var(--accent)', color: 'var(--accent-text)' }}
      >
        Skip to content
      </a>

      {mobileOpen ? (
        <button
          type="button"
          aria-label="Close navigation"
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={close}
        />
      ) : null}

      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex w-60 shrink-0 flex-col border-r transition-transform duration-200 lg:static lg:translate-x-0',
          mobileOpen ? 'translate-x-0' : '-translate-x-full',
        )}
        style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
      >
        <div
          className="flex h-12 items-center justify-between border-b px-3"
          style={{ borderColor: 'var(--border)' }}
        >
          <NavLink to="/" className="flex items-center gap-2">
            <svg viewBox="0 0 32 32" className="size-6" aria-hidden="true">
              <rect width="32" height="32" rx="7" fill="var(--accent)" />
              <circle cx="14" cy="14" r="7" fill="none" stroke="var(--accent-text)" strokeWidth="2.5" />
              <line x1="19.5" y1="19.5" x2="25" y2="25" stroke="var(--accent-text)" strokeWidth="3" strokeLinecap="round" />
            </svg>
            <span className="text-sm font-semibold tracking-tight">DroidScope</span>
          </NavLink>
          <button
            type="button"
            onClick={close}
            aria-label="Close navigation"
            className="cursor-pointer rounded-sm p-1 lg:hidden"
          >
            <X className="size-4" />
          </button>
        </div>

        <nav aria-label="Main" className="flex-1 overflow-y-auto px-2 py-3">
          <NavSection title="Overview" items={PRIMARY_NAV} onNavigate={close} />
          <NavSection title="Analysis" items={ANALYSIS_NAV} onNavigate={close} />
          <NavSection title="Tools" items={TOOLS_NAV} onNavigate={close} />
        </nav>

        <div className="border-t px-3 py-2 text-[11px]" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-center justify-between">
            <span className="text-subtle">
              {health.data ? `v${health.data.version}` : '—'}
            </span>
            {health.isError ? (
              <StatusBadge tone="error">API offline</StatusBadge>
            ) : health.data ? (
              <StatusBadge tone={health.data.status === 'ok' ? 'ok' : 'warn'}>
                {health.data.status === 'ok' ? 'Connected' : 'Degraded'}
              </StatusBadge>
            ) : null}
          </div>
          {health.data?.queue_pending ? (
            <div className="mt-1 text-subtle">{health.data.queue_pending} job(s) pending</div>
          ) : null}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header
          className="flex h-12 shrink-0 items-center justify-between gap-3 border-b px-4"
          style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
        >
          <button
            type="button"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
            className="cursor-pointer rounded-sm p-1 lg:hidden"
          >
            <Menu className="size-5" />
          </button>
          <div className="min-w-0 flex-1" />
          <button
            type="button"
            onClick={toggle}
            aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
            className="flex cursor-pointer items-center gap-1.5 rounded-sm border px-2 py-1 text-xs transition-colors"
            style={{ borderColor: 'var(--border)' }}
          >
            {dark ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
            <span className="hidden sm:inline">{dark ? 'Light' : 'Dark'}</span>
          </button>
        </header>

        <main id="main-content" className="min-w-0 flex-1 overflow-y-auto p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
