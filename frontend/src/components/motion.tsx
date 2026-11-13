/**
 * Motion components.
 *
 * Each of these does one of three jobs: orient the reader (where did this come
 * from), explain that something is loading or changing, or acknowledge input.
 * Anything purely decorative is deliberately absent.
 *
 * All of them respect `prefers-reduced-motion`: the CSS-driven ones through
 * the media query in `motion.css`, and `CountUp` through `useReducedMotion`,
 * because a JavaScript tween cannot be disabled by CSS.
 */

import { useEffect, useRef, useState, type ElementType, type ReactNode } from 'react';
import { cn } from '@/lib/cn';
import { useReducedMotion } from '@/hooks/useReducedMotion';

type RevealVariant = 'rise' | 'fade' | 'slide' | 'scale';

const VARIANT_CLASS: Record<RevealVariant, string> = {
  rise: 'ds-animate-rise',
  fade: 'ds-animate-fade',
  slide: 'ds-animate-slide-in',
  scale: 'ds-animate-scale-in',
};

/** Animates its children into place once, on mount. */
export function Reveal({
  children,
  variant = 'rise',
  delay = 0,
  as: Tag = 'div',
  className,
}: {
  children: ReactNode;
  variant?: RevealVariant;
  /** Milliseconds. Use sparingly; a stagger container is usually better. */
  delay?: number;
  as?: ElementType;
  className?: string;
}) {
  return (
    <Tag
      className={cn(VARIANT_CLASS[variant], className)}
      style={delay ? { animationDelay: `${delay}ms` } : undefined}
    >
      {children}
    </Tag>
  );
}

/**
 * Staggers direct children so a list resolves in reading order.
 *
 * `rows` switches to the tighter timing used for table bodies, where the
 * standard cadence would feel sluggish across twenty rows.
 */
export function Stagger({
  children,
  rows = false,
  as: Tag = 'div',
  className,
}: {
  children: ReactNode;
  rows?: boolean;
  as?: ElementType;
  className?: string;
}) {
  return (
    <Tag className={cn(rows ? 'ds-stagger-rows' : 'ds-stagger', className)}>{children}</Tag>
  );
}

/**
 * Counts a number up to its value.
 *
 * Used only on dashboard and scan totals, where the movement draws the eye to
 * a figure that changed. It is not applied to every number on the page.
 */
export function CountUp({
  value,
  duration = 600,
  className,
}: {
  value: number;
  duration?: number;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const [display, setDisplay] = useState(() => (reduced ? value : 0));
  const previous = useRef(value);
  const frame = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (reduced || duration <= 0) {
      setDisplay(value);
      previous.current = value;
      return;
    }

    const from = previous.current;
    const delta = value - from;
    if (delta === 0) {
      setDisplay(value);
      return;
    }

    const started = performance.now();
    const tick = (now: number) => {
      const progress = Math.min((now - started) / duration, 1);
      // easeOutCubic: fast at first, settling into the final value.
      const eased = 1 - (1 - progress) ** 3;
      setDisplay(Math.round(from + delta * eased));
      if (progress < 1) {
        frame.current = requestAnimationFrame(tick);
      } else {
        previous.current = value;
      }
    };
    frame.current = requestAnimationFrame(tick);

    return () => {
      if (frame.current !== undefined) cancelAnimationFrame(frame.current);
      previous.current = value;
    };
  }, [value, duration, reduced]);

  // The accessible name is always the real value, never an intermediate one.
  return (
    <span className={className} aria-label={String(value)}>
      <span aria-hidden="true">{display.toLocaleString()}</span>
    </span>
  );
}

/** A placeholder block sized like the content it stands in for. */
export function Skeleton({
  className,
  width,
  height,
}: {
  className?: string;
  width?: string | number;
  height?: string | number;
}) {
  return (
    <span
      aria-hidden="true"
      className={cn('ds-skeleton block', className)}
      style={{ width, height }}
    />
  );
}

/**
 * A skeleton table body.
 *
 * Preferred over a spinner wherever the shape of the incoming content is
 * known: it reserves the space, so the layout does not jump when data lands.
 */
export function SkeletonRows({
  rows = 6,
  columns = 4,
}: {
  rows?: number;
  columns?: number;
}) {
  return (
    <tbody aria-busy="true">
      {Array.from({ length: rows }, (_, rowIndex) => (
        <tr key={rowIndex}>
          {Array.from({ length: columns }, (_, columnIndex) => (
            <td key={columnIndex}>
              <Skeleton
                height="0.85rem"
                // Varying widths read as content rather than as a grid.
                width={columnIndex === 1 ? '70%' : columnIndex === 0 ? '45%' : '55%'}
              />
            </td>
          ))}
        </tr>
      ))}
    </tbody>
  );
}

/** A skeleton for a stat tile row. */
export function SkeletonTiles({ count = 6 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6" aria-busy="true">
      {Array.from({ length: count }, (_, index) => (
        <div key={index} className="ds-surface px-3 py-2.5">
          <Skeleton height="0.6rem" width="55%" />
          <Skeleton className="mt-2" height="1.5rem" width="40%" />
        </div>
      ))}
    </div>
  );
}

/**
 * Marks content as live-updating.
 *
 * The gentle opacity cycle is reserved for things genuinely in progress — a
 * running scan, an active session — so it carries meaning rather than being
 * ambient decoration.
 */
export function Live({ children, active = true }: { children: ReactNode; active?: boolean }) {
  return <span className={active ? 'ds-animate-breathe' : undefined}>{children}</span>;
}
