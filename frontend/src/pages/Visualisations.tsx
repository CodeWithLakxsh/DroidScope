/** Graph and chart views over a scan's data. */

import { useParams } from 'react-router-dom';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ScanPicker } from '@/components/ScanPicker';
import { ComponentGraph } from '@/visualization/ComponentGraph';
import { PipelineGraph } from '@/visualization/PipelineGraph';
import { useApk, useFindings, useScan } from '@/hooks/queries';
import {
  Card,
  CardHeader,
  EmptyState,
  LoadingState,
  Note,
  PageHeader,
} from '@/components/ui';
import { SEVERITY_ORDER, titleCase } from '@/lib/format';

export default function Visualisations() {
  const { scanId } = useParams<{ scanId: string }>();
  const scan = useScan(scanId);
  const apk = useApk(scan.data?.apk_id);
  const findings = useFindings(scanId, { limit: 500 });

  if (!scanId) {
    return (
      <>
        <PageHeader title="Visualisations" />
        <ScanPicker basePath="/graphs" />
      </>
    );
  }

  if (scan.isLoading) return <LoadingState label="Loading scan" />;

  const severityData = SEVERITY_ORDER.map((severity) => ({
    name: titleCase(severity),
    severity,
    value: scan.data?.severity_counts[severity] ?? 0,
  })).filter((item) => item.value > 0);

  const categoryCounts = new Map<string, number>();
  (findings.data?.items ?? []).forEach((finding) => {
    categoryCounts.set(finding.category, (categoryCounts.get(finding.category) ?? 0) + 1);
  });
  const categoryData = [...categoryCounts.entries()]
    .map(([category, count]) => ({ name: titleCase(category), value: count }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 10);

  const CATEGORY_COLOURS = [
    'var(--accent)', '#3b82f6', '#8b5cf6', '#f59e0b', '#ef4444',
    '#10b981', '#6366f1', '#ec4899', '#14b8a6', '#64748b',
  ];

  return (
    <>
      <PageHeader
        title="Visualisations"
        description="Diagrams built from this scan's recorded data."
        actions={<ScanPicker basePath="/graphs" currentScanId={scanId} />}
      />

      <div className="mb-4">
        <Note tone="accent" title="Drawn from evidence only">
          Nodes and edges come from the parsed manifest and from analyzer executions actually
          recorded for this scan. No relationship is inferred without data behind it.
        </Note>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Findings by severity" />
          {severityData.length === 0 ? (
            <EmptyState title="No findings to chart" />
          ) : (
            <div className="p-3">
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={severityData} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
                  <CartesianGrid strokeDasharray="2 4" stroke="var(--border)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                  <Tooltip
                    cursor={{ fill: 'var(--surface-hover)' }}
                    contentStyle={{
                      backgroundColor: 'var(--surface-raised)',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontSize: 12,
                    }}
                  />
                  <Bar dataKey="value" name="Findings" radius={[2, 2, 0, 0]}>
                    {severityData.map((item) => (
                      <Cell key={item.severity} fill={`var(--severity-${item.severity})`} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card>
          <CardHeader title="Findings by category" />
          {categoryData.length === 0 ? (
            <EmptyState title="No findings to chart" />
          ) : (
            <div className="p-3">
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie
                    data={categoryData}
                    dataKey="value"
                    nameKey="name"
                    cx="40%"
                    cy="50%"
                    outerRadius={80}
                    innerRadius={42}
                    paddingAngle={2}
                  >
                    {categoryData.map((entry, index) => (
                      <Cell key={entry.name} fill={CATEGORY_COLOURS[index % CATEGORY_COLOURS.length]} />
                    ))}
                  </Pie>
                  <Legend
                    layout="vertical"
                    align="right"
                    verticalAlign="middle"
                    wrapperStyle={{ fontSize: 10 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'var(--surface-raised)',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader
          title="Analysis pipeline"
          description="Stages recorded for this scan, with each analyzer's status and finding count."
        />
        {scan.data ? <PipelineGraph executions={scan.data.executions} /> : <LoadingState />}
      </Card>

      <Card className="mt-4">
        <CardHeader
          title="Application component graph"
          description="Manifest components and the permissions that guard them. ⚠ marks an exported component."
        />
        {apk.isLoading ? (
          <LoadingState />
        ) : apk.data ? (
          <ComponentGraph metadata={apk.data.apk_metadata} />
        ) : (
          <EmptyState title="No manifest data" />
        )}
      </Card>
    </>
  );
}
