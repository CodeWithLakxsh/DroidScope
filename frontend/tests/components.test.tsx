import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import {
  EmptyState,
  ErrorState,
  JobStatusBadge,
  ProgressBar,
  SeverityBadge,
  StatTile,
  StatusBadge,
} from '@/components/ui';

function wrap(ui: React.ReactNode) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe('SeverityBadge', () => {
  it('shows a text label, not colour alone', () => {
    wrap(<SeverityBadge severity="critical" />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });

  it('keeps the label available to screen readers when visually hidden', () => {
    wrap(<SeverityBadge severity="high" showLabel={false} />);
    expect(screen.getByText('High')).toBeInTheDocument();
  });
});

describe('StatusBadge', () => {
  it('renders its children', () => {
    wrap(<StatusBadge tone="ok">Connected</StatusBadge>);
    expect(screen.getByText('Connected')).toBeInTheDocument();
  });
});

describe('JobStatusBadge', () => {
  it('humanises an underscored status', () => {
    wrap(<JobStatusBadge status="timed_out" />);
    expect(screen.getByText('timed out')).toBeInTheDocument();
  });
});

describe('EmptyState', () => {
  it('shows a title and description', () => {
    wrap(
      <EmptyState title="No applications yet" description="Upload an APK to begin." />,
    );
    expect(screen.getByRole('heading', { name: 'No applications yet' })).toBeInTheDocument();
    expect(screen.getByText('Upload an APK to begin.')).toBeInTheDocument();
  });
});

describe('ErrorState', () => {
  it('exposes the error through an alert role', () => {
    wrap(<ErrorState error={new Error('the API is unreachable')} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('the API is unreachable')).toBeInTheDocument();
  });
});

describe('ProgressBar', () => {
  it('reports progress to assistive technology', () => {
    wrap(<ProgressBar value={0.42} label="Scan progress" />);
    const bar = screen.getByRole('progressbar', { name: 'Scan progress' });
    expect(bar).toHaveAttribute('aria-valuenow', '42');
  });

  it('clamps an out-of-range value', () => {
    wrap(<ProgressBar value={1.8} />);
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100');
  });
});

describe('StatTile', () => {
  it('links when given a destination', () => {
    wrap(<StatTile label="Findings" value={52} href="/findings" />);
    expect(screen.getByRole('link')).toHaveAttribute('href', '/findings');
    expect(screen.getByText('52')).toBeInTheDocument();
  });
});
