import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { CountUp, Live, Reveal, Skeleton, SkeletonRows, Stagger } from '@/components/motion';
import { ProgressBar } from '@/components/ui';

/** Make `prefers-reduced-motion` report a given value for one test. */
function setReducedMotion(reduced: boolean) {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: reduced && query.includes('prefers-reduced-motion'),
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })) as never;
}

describe('Reveal', () => {
  it('applies the variant class', () => {
    render(<Reveal variant="rise">content</Reveal>);
    expect(screen.getByText('content')).toHaveClass('ds-animate-rise');
  });

  it('supports a delay without affecting content', () => {
    render(<Reveal delay={120}>delayed</Reveal>);
    const element = screen.getByText('delayed');
    expect(element).toHaveStyle({ animationDelay: '120ms' });
  });
});

describe('Stagger', () => {
  it('uses the dense cadence for table rows', () => {
    const { container } = render(
      <table>
        <Stagger as="tbody" rows>
          <tr><td>one</td></tr>
        </Stagger>
      </table>,
    );
    expect(container.querySelector('tbody')).toHaveClass('ds-stagger-rows');
  });

  it('uses the standard cadence otherwise', () => {
    const { container } = render(<Stagger><div>a</div></Stagger>);
    expect(container.firstChild).toHaveClass('ds-stagger');
  });
});

describe('CountUp', () => {
  it('reaches the target value', async () => {
    setReducedMotion(false);
    render(<CountUp value={52} duration={30} />);
    await waitFor(() => expect(screen.getByLabelText('52')).toHaveTextContent('52'));
  });

  it('exposes the real value to assistive technology immediately', () => {
    setReducedMotion(false);
    render(<CountUp value={99} duration={5000} />);
    // The accessible name is the true value even mid-animation.
    expect(screen.getByLabelText('99')).toBeInTheDocument();
  });

  it('jumps straight to the value when motion is reduced', () => {
    setReducedMotion(true);
    render(<CountUp value={42} duration={5000} />);
    expect(screen.getByLabelText('42')).toHaveTextContent('42');
  });

  it('formats large numbers readably', async () => {
    setReducedMotion(true);
    render(<CountUp value={12345} />);
    await waitFor(() =>
      expect(screen.getByLabelText('12345').textContent).toBe((12345).toLocaleString()),
    );
  });
});

describe('Skeleton', () => {
  it('is hidden from assistive technology', () => {
    const { container } = render(<Skeleton width="50%" height="1rem" />);
    const element = container.firstChild as HTMLElement;
    expect(element).toHaveAttribute('aria-hidden', 'true');
    expect(element).toHaveClass('ds-skeleton');
  });

  it('renders a busy table body with the requested shape', () => {
    const { container } = render(
      <table><SkeletonRows rows={3} columns={4} /></table>,
    );
    expect(container.querySelector('tbody')).toHaveAttribute('aria-busy', 'true');
    expect(container.querySelectorAll('tr')).toHaveLength(3);
    expect(container.querySelectorAll('td')).toHaveLength(12);
  });
});

describe('Live', () => {
  it('animates only while active', () => {
    const { rerender, container } = render(<Live active>status</Live>);
    expect(container.firstChild).toHaveClass('ds-animate-breathe');
    rerender(<Live active={false}>status</Live>);
    expect(container.firstChild).not.toHaveClass('ds-animate-breathe');
  });
});

describe('ProgressBar', () => {
  it('reports a determinate value', () => {
    render(<ProgressBar value={0.42} label="Scan progress" />);
    expect(screen.getByRole('progressbar', { name: 'Scan progress' })).toHaveAttribute(
      'aria-valuenow',
      '42',
    );
  });

  it('omits aria-valuenow when indeterminate', () => {
    // Omitting the value is how assistive technology is told the proportion
    // is genuinely unknown.
    render(<ProgressBar value={0} indeterminate label="Queued" />);
    const bar = screen.getByRole('progressbar', { name: 'Queued' });
    expect(bar).not.toHaveAttribute('aria-valuenow');
    expect(bar).toHaveClass('ds-progress-indeterminate');
  });
});
