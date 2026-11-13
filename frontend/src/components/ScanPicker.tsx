/**
 * Scan selector used by every analysis view.
 *
 * Analysis pages need a scan to work with. Rather than failing when none is in
 * the URL, they render this picker, which defaults to the most recent completed
 * scan so the page is useful immediately.
 */

import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScans } from '@/hooks/queries';
import { Card, EmptyState, LinkButton, LoadingState, Select } from '@/components/ui';
import { formatRelative } from '@/lib/format';

export function ScanPicker({
  basePath,
  currentScanId,
  label = 'Scan',
}: {
  basePath: string;
  currentScanId?: string;
  label?: string;
}) {
  const navigate = useNavigate();
  const { data, isLoading } = useScans({ limit: 50, status: 'completed' });

  // Land on the newest completed scan when the route carries none.
  useEffect(() => {
    if (!currentScanId && data?.items.length) {
      navigate(`${basePath}/${data.items[0].id}`, { replace: true });
    }
  }, [currentScanId, data, basePath, navigate]);

  if (isLoading) return <LoadingState label="Loading scans" />;

  if (!data || data.items.length === 0) {
    return (
      <Card>
        <EmptyState
          title="No completed scans"
          description="Run an analysis first; this view reads data produced by a completed scan."
          action={<LinkButton to="/upload" variant="primary">Upload an APK</LinkButton>}
        />
      </Card>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <label htmlFor="scan-picker" className="text-xs font-medium text-muted">
        {label}
      </label>
      <Select
        id="scan-picker"
        value={currentScanId ?? ''}
        onChange={(event) => navigate(`${basePath}/${event.target.value}`)}
        className="w-auto min-w-[18rem]"
      >
        {data.items.map((scan) => (
          <option key={scan.id} value={scan.id}>
            {scan.package_name ?? scan.apk_id.slice(0, 8)} · {scan.profile} ·{' '}
            {formatRelative(scan.created_at)} · {scan.findings_total} findings
          </option>
        ))}
      </Select>
    </div>
  );
}
