import { lazy, Suspense } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { LoadingState } from '@/components/ui';

// Heavy views (Monaco, React Flow, charts) load on demand.
const Dashboard = lazy(() => import('@/pages/Dashboard'));
const UploadPage = lazy(() => import('@/pages/Upload'));
const Applications = lazy(() => import('@/pages/Applications'));
const ApplicationOverview = lazy(() => import('@/pages/ApplicationOverview'));
const Scans = lazy(() => import('@/pages/Scans'));
const ScanDetailPage = lazy(() => import('@/pages/ScanDetail'));
const Findings = lazy(() => import('@/pages/Findings'));
const CodeExplorer = lazy(() => import('@/pages/CodeExplorer'));
const ManifestExplorer = lazy(() => import('@/pages/ManifestExplorer'));
const Indicators = lazy(() => import('@/pages/Indicators'));
const BinaryAnalysis = lazy(() => import('@/pages/BinaryAnalysis'));
const Visualisations = lazy(() => import('@/pages/Visualisations'));
const Compare = lazy(() => import('@/pages/Compare'));
const DynamicAnalysis = lazy(() => import('@/pages/DynamicAnalysis'));
const Reports = lazy(() => import('@/pages/Reports'));
const SettingsPage = lazy(() => import('@/pages/Settings'));
const NotFound = lazy(() => import('@/pages/NotFound'));

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route
            path="/"
            element={
              <Suspense fallback={<LoadingState />}>
                <Dashboard />
              </Suspense>
            }
          />
          {[
            { path: '/upload', element: <UploadPage /> },
            { path: '/applications', element: <Applications /> },
            { path: '/applications/:apkId', element: <ApplicationOverview /> },
            { path: '/scans', element: <Scans /> },
            { path: '/scans/:scanId', element: <ScanDetailPage /> },
            { path: '/findings', element: <Findings /> },
            { path: '/findings/:scanId', element: <Findings /> },
            { path: '/code', element: <CodeExplorer /> },
            { path: '/code/:scanId', element: <CodeExplorer /> },
            { path: '/manifest', element: <ManifestExplorer /> },
            { path: '/manifest/:apkId', element: <ManifestExplorer /> },
            { path: '/indicators', element: <Indicators /> },
            { path: '/indicators/:scanId', element: <Indicators /> },
            { path: '/binary', element: <BinaryAnalysis /> },
            { path: '/binary/:scanId', element: <BinaryAnalysis /> },
            { path: '/graphs', element: <Visualisations /> },
            { path: '/graphs/:scanId', element: <Visualisations /> },
            { path: '/compare', element: <Compare /> },
            { path: '/dynamic', element: <DynamicAnalysis /> },
            { path: '/reports', element: <Reports /> },
            { path: '/reports/:scanId', element: <Reports /> },
            { path: '/settings', element: <SettingsPage /> },
          ].map((route) => (
            <Route
              key={route.path}
              path={route.path}
              element={<Suspense fallback={<LoadingState />}>{route.element}</Suspense>}
            />
          ))}
          <Route path="/dashboard" element={<Navigate to="/" replace />} />
          <Route
            path="*"
            element={
              <Suspense fallback={<LoadingState />}>
                <NotFound />
              </Suspense>
            }
          />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
