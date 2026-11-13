/**
 * Shared UI primitives.
 *
 * Accessibility rules applied throughout:
 * - status and severity always pair colour with a glyph and a text label;
 * - every interactive element is a real button or link, reachable by keyboard;
 * - focus rings are never removed (see styles/index.css).
 */

import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { cn } from '@/lib/cn';
import { SEVERITY_GLYPH, SEVERITY_LABEL } from '@/lib/format';
import type { Severity } from '@/types/api';

/* ---------------------------------------------------------------- surfaces */

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('ds-surface', className)} {...props} />;
}

export function CardHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-start justify-between gap-3 border-b px-4 py-3',
        className,
      )}
      style={{ borderColor: 'var(--border)' }}
    >
      <div className="min-w-0">
        <h2 className="text-sm font-semibold">{title}</h2>
        {description ? <p className="mt-0.5 text-xs text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description ? (
          <p className="mt-1 max-w-3xl text-sm text-muted">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

/* ----------------------------------------------------------------- buttons */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
type ButtonSize = 'sm' | 'md';

const BUTTON_BASE =
  'inline-flex items-center justify-center gap-1.5 rounded-sm font-medium transition-colors ' +
  'duration-150 disabled:cursor-not-allowed disabled:opacity-50 cursor-pointer whitespace-nowrap';

const BUTTON_SIZES: Record<ButtonSize, string> = {
  // 32px tall minimum; comfortably clickable while staying dense.
  sm: 'h-8 px-2.5 text-xs',
  md: 'h-9 px-3.5 text-sm',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = 'secondary', size = 'sm', style, ...props },
  ref,
) {
  const variantStyle: Record<ButtonVariant, React.CSSProperties> = {
    primary: { backgroundColor: 'var(--accent)', color: 'var(--accent-text)', border: '1px solid var(--accent)' },
    secondary: { backgroundColor: 'var(--surface-raised)', color: 'var(--text)', border: '1px solid var(--border)' },
    ghost: { backgroundColor: 'transparent', color: 'var(--text-muted)', border: '1px solid transparent' },
    danger: { backgroundColor: 'var(--status-error-bg)', color: 'var(--status-error)', border: '1px solid var(--status-error)' },
  };
  return (
    <button
      ref={ref}
      className={cn(BUTTON_BASE, BUTTON_SIZES[size], 'hover:brightness-[0.97]', className)}
      style={{ ...variantStyle[variant], ...style }}
      {...props}
    />
  );
});

export function LinkButton({
  to,
  children,
  className,
  variant = 'secondary',
  size = 'sm',
}: {
  to: string;
  children: ReactNode;
  className?: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
}) {
  const variantStyle: Record<ButtonVariant, React.CSSProperties> = {
    primary: { backgroundColor: 'var(--accent)', color: 'var(--accent-text)', border: '1px solid var(--accent)' },
    secondary: { backgroundColor: 'var(--surface-raised)', color: 'var(--text)', border: '1px solid var(--border)' },
    ghost: { backgroundColor: 'transparent', color: 'var(--text-muted)', border: '1px solid transparent' },
    danger: { backgroundColor: 'var(--status-error-bg)', color: 'var(--status-error)', border: '1px solid var(--status-error)' },
  };
  return (
    <Link
      to={to}
      className={cn(BUTTON_BASE, BUTTON_SIZES[size], className)}
      style={variantStyle[variant]}
    >
      {children}
    </Link>
  );
}

/* ------------------------------------------------------------------ badges */

export function SeverityBadge({
  severity,
  showLabel = true,
  className,
}: {
  severity: Severity;
  showLabel?: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-xs border px-1.5 py-0.5 text-xs font-semibold',
        className,
      )}
      style={{
        color: `var(--severity-${severity})`,
        backgroundColor: `var(--severity-${severity}-bg)`,
        borderColor: `var(--severity-${severity})`,
      }}
    >
      {/* The glyph is decorative; the adjacent text carries the meaning. */}
      <span aria-hidden="true">{SEVERITY_GLYPH[severity]}</span>
      {showLabel ? SEVERITY_LABEL[severity] : <span className="sr-only">{SEVERITY_LABEL[severity]}</span>}
    </span>
  );
}

type StatusTone = 'ok' | 'warn' | 'error' | 'neutral' | 'accent';

const STATUS_GLYPH: Record<StatusTone, string> = {
  ok: '✓',
  warn: '!',
  error: '✕',
  neutral: '·',
  accent: '→',
};

export function StatusBadge({
  tone,
  children,
  className,
  glyph = true,
  title,
}: {
  tone: StatusTone;
  children: ReactNode;
  className?: string;
  glyph?: boolean;
  title?: string;
}) {
  const palette: Record<StatusTone, React.CSSProperties> = {
    ok: { color: 'var(--status-ok)', backgroundColor: 'var(--status-ok-bg)', borderColor: 'var(--status-ok)' },
    warn: { color: 'var(--status-warn)', backgroundColor: 'var(--status-warn-bg)', borderColor: 'var(--status-warn)' },
    error: { color: 'var(--status-error)', backgroundColor: 'var(--status-error-bg)', borderColor: 'var(--status-error)' },
    neutral: { color: 'var(--text-muted)', backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border)' },
    accent: { color: 'var(--accent)', backgroundColor: 'transparent', borderColor: 'var(--accent)' },
  };
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-xs border px-1.5 py-0.5 text-xs font-medium',
        className,
      )}
      style={palette[tone]}
      title={title}
    >
      {glyph ? <span aria-hidden="true">{STATUS_GLYPH[tone]}</span> : null}
      {children}
    </span>
  );
}

const JOB_STATUS_TONE: Record<string, StatusTone> = {
  completed: 'ok',
  running: 'accent',
  queued: 'neutral',
  failed: 'error',
  cancelled: 'warn',
  timed_out: 'warn',
  unavailable: 'warn',
  skipped: 'neutral',
  stopped: 'ok',
  created: 'neutral',
  preparing: 'accent',
  stopping: 'warn',
};

export function JobStatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <StatusBadge tone={JOB_STATUS_TONE[status] ?? 'neutral'} className={className}>
      {status.replace(/_/g, ' ')}
    </StatusBadge>
  );
}

export function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn('ds-mono inline-flex rounded-xs border px-1.5 py-0.5 text-[11px]', className)}
      style={{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border)' }}
    >
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ states */

export function Spinner({ className, label = 'Loading' }: { className?: string; label?: string }) {
  return (
    <span role="status" aria-live="polite" className={cn('inline-flex items-center gap-2', className)}>
      <svg className="size-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
        <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      </svg>
      <span className="sr-only">{label}</span>
    </span>
  );
}

export function LoadingState({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 px-4 py-12 text-sm text-muted">
      <Spinner label={label} />
      <span aria-hidden="true">{label}…</span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
  icon,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      {icon ? <div className="mb-3 text-subtle">{icon}</div> : null}
      <h3 className="text-sm font-semibold">{title}</h3>
      {description ? (
        <p className="mt-1.5 max-w-md text-sm text-muted">{description}</p>
      ) : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function ErrorState({
  title = 'Something went wrong',
  error,
  onRetry,
}: {
  title?: string;
  error?: unknown;
  onRetry?: () => void;
}) {
  const message =
    error instanceof Error ? error.message : typeof error === 'string' ? error : undefined;
  return (
    <div
      role="alert"
      className="flex flex-col items-center justify-center px-6 py-12 text-center"
    >
      <StatusBadge tone="error">Error</StatusBadge>
      <h3 className="mt-3 text-sm font-semibold">{title}</h3>
      {message ? <p className="mt-1.5 max-w-lg text-sm text-muted">{message}</p> : null}
      {onRetry ? (
        <Button className="mt-4" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ inputs */

export function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
  className,
}: {
  label: string;
  htmlFor: string;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex flex-col gap-1', className)}>
      {/* A visible label, never a placeholder standing in for one. */}
      <label htmlFor={htmlFor} className="text-xs font-medium">
        {label}
      </label>
      {children}
      {error ? (
        <p id={`${htmlFor}-error`} className="text-xs" style={{ color: 'var(--status-error)' }}>
          {error}
        </p>
      ) : hint ? (
        <p id={`${htmlFor}-hint`} className="text-xs text-subtle">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

const CONTROL_CLASS =
  'h-8 w-full rounded-sm border px-2 text-sm transition-colors duration-150 ' +
  'placeholder:text-[var(--text-subtle)]';

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, style, ...props }, ref) {
    return (
      <input
        ref={ref}
        className={cn(CONTROL_CLASS, className)}
        style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', ...style }}
        {...props}
      />
    );
  },
);

export const Select = forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, style, children, ...props }, ref) {
    return (
      <select
        ref={ref}
        className={cn(CONTROL_CLASS, 'cursor-pointer pr-7', className)}
        style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', ...style }}
        {...props}
      >
        {children}
      </select>
    );
  },
);

/* ------------------------------------------------------------------ tables */

export function DataTable({
  columns,
  children,
  caption,
  className,
  fixed = false,
}: {
  columns: { key: string; label: ReactNode; width?: string; align?: 'left' | 'right' }[];
  children: ReactNode;
  caption?: string;
  className?: string;
  /** Honour the declared column widths instead of sizing to content. */
  fixed?: boolean;
}) {
  return (
    <div className={cn('ds-scroll-x', className)}>
      <table className={cn('ds-table', fixed && 'table-fixed')}>
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                style={{ width: column.width, textAlign: column.align ?? 'left' }}
              >
                {column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function KeyValue({
  rows,
  className,
}: {
  rows: { label: ReactNode; value: ReactNode; mono?: boolean }[];
  className?: string;
}) {
  return (
    <dl className={cn('divide-y', className)} style={{ borderColor: 'var(--border)' }}>
      {rows.map((row, index) => (
        <div key={index} className="grid grid-cols-[minmax(7rem,30%)_1fr] gap-3 px-4 py-2">
          <dt className="text-xs font-medium text-muted">{row.label}</dt>
          <dd className={cn('min-w-0 text-xs break-words', row.mono && 'ds-mono')}>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone,
  href,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: Severity | 'accent';
  href?: string;
}) {
  const colour =
    tone && tone !== 'accent' ? `var(--severity-${tone})` : tone === 'accent' ? 'var(--accent)' : 'var(--text)';
  const content = (
    <>
      <div className="text-[11px] font-medium tracking-wide text-muted uppercase">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums" style={{ color: colour }}>
        {value}
      </div>
      {hint ? <div className="mt-0.5 text-[11px] text-subtle">{hint}</div> : null}
    </>
  );
  if (href) {
    return (
      <Link to={href} className="ds-surface block px-3 py-2.5 transition-colors hover:brightness-[0.98]">
        {content}
      </Link>
    );
  }
  return <div className="ds-surface px-3 py-2.5">{content}</div>;
}

export function Note({
  tone = 'neutral',
  title,
  children,
}: {
  tone?: StatusTone;
  title?: ReactNode;
  children: ReactNode;
}) {
  const palette: Record<StatusTone, string> = {
    ok: 'var(--status-ok)',
    warn: 'var(--status-warn)',
    error: 'var(--status-error)',
    neutral: 'var(--border-strong)',
    accent: 'var(--accent)',
  };
  return (
    <div
      className="rounded-sm border-l-2 px-3 py-2 text-xs"
      style={{ borderLeftColor: palette[tone], backgroundColor: 'var(--surface-sunken)' }}
    >
      {title ? <div className="mb-0.5 font-semibold">{title}</div> : null}
      <div className="text-muted">{children}</div>
    </div>
  );
}

export function ProgressBar({ value, label }: { value: number; label?: string }) {
  const percent = Math.round(Math.min(Math.max(value, 0), 1) * 100);
  return (
    <div
      role="progressbar"
      aria-valuenow={percent}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label ?? 'Progress'}
      className="h-1.5 w-full overflow-hidden rounded-full"
      style={{ backgroundColor: 'var(--surface-hover)' }}
    >
      <div
        className="h-full rounded-full transition-[width] duration-300"
        style={{ width: `${percent}%`, backgroundColor: 'var(--accent)' }}
      />
    </div>
  );
}
