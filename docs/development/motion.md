# Motion design

DroidScope is a dense tool people use for hours. Motion here is subordinate to
that: it exists to orient, explain or acknowledge, and nothing is animated
because it looks pleasant.

## Rules

| Rule | Why |
|---|---|
| Animate only `transform` and `opacity` | Both are compositor properties. Animating `width`, `height` or `top` forces layout on every frame |
| Durations 90–500 ms | Long enough to read as motion, short enough not to delay a repeated task |
| Exits faster than entrances | Dismissal should feel immediate; arrival should be followable |
| Every effect collapses under `prefers-reduced-motion` | Not shortened — suppressed, with the end state applied |
| Motion never carries information alone | Anything a pulse conveys is also stated in text |

## Tokens

Defined in `src/styles/motion.css`:

```css
--duration-instant: 90ms;   /* press feedback */
--duration-fast:   150ms;   /* hover, small reveals */
--duration-base:   220ms;   /* panels, fades */
--duration-slow:   350ms;   /* page and list entrances */
--duration-slower: 500ms;   /* progress transitions */

--ease-out:    cubic-bezier(0.25, 0.46, 0.45, 0.94);  /* entrances */
--ease-in:     cubic-bezier(0.55, 0.06, 0.68, 0.19);  /* exits */
--ease-in-out: cubic-bezier(0.45, 0.05, 0.55, 0.95);  /* loops */
--ease-spring: cubic-bezier(0.34, 1.56, 0.64, 1);     /* acknowledgement */
```

## What each effect is for

| Effect | Where | Job |
|---|---|---|
| Route entrance (`ds-animate-rise`, keyed on pathname) | Every page | Orient: the shell stays put, so the content needs to announce that it changed |
| Stagger (`ds-stagger`, `ds-stagger-rows`) | Stat tiles, table bodies | Orient: a list resolves in reading order rather than arriving as a block |
| Skeletons (`ds-skeleton`, `SkeletonRows`, `SkeletonTiles`) | Dashboard, tables | Explain: reserves the layout so nothing jumps, and shows the shape of what is coming |
| Count-up (`CountUp`) | Totals only | Explain: draws the eye to a figure that changed. Not used on every number |
| Indeterminate progress | A queued scan | Explain: progress is genuinely unknown, and `aria-valuenow` is omitted to say so |
| Breathe (`Live`) | A running scan's status badge | Explain: this is in progress. Reserved for genuinely live items |
| Press (`ds-press`) | Every button | Acknowledge: scale, not colour, so it reads the same in both themes and for colour-blind users |
| Lift (`ds-lift`) | Linked tiles and cards | Acknowledge: signals the surface is interactive |
| Slide-in (`ds-animate-slide-in`) | Finding detail panel | Orient: the panel comes from the side it occupies |

## Components

```tsx
import { CountUp, Live, Reveal, Skeleton, SkeletonRows, Stagger } from '@/components/motion';

<Reveal variant="rise">…</Reveal>
<Stagger rows>{rows}</Stagger>
<CountUp value={52} />
<Skeleton width="60%" height="1rem" />
<Live active={scan.status === 'running'}><JobStatusBadge … /></Live>
```

`DataTable` takes `staggerRows`; `ProgressBar` takes `indeterminate`.

## Accessibility

`prefers-reduced-motion: reduce` is handled explicitly rather than by a blanket
`animation: none`. The entrance utilities use `animation-fill-mode: both`, so
suppressing the animation without resetting `opacity` and `transform` would
leave content stranded at opacity 0 — invisible, and worse than no animation at
all. The reduced-motion block therefore resets both properties.

`CountUp` is JavaScript and cannot be stopped by CSS, so it reads the
preference through `useReducedMotion()` and renders the final value
immediately. Its accessible name is always the true value, never an
intermediate frame, so a screen reader never announces a number that is
counting.

This is verified, not assumed: `frontend/tests/e2e/reduced-motion.spec.ts` runs
the real UI with the preference set and asserts that content is visible, that
`animationName` computes to `none`, and that the workflow still completes.

## Adding motion

Ask which of the three jobs it does. If the answer is "it looks nice", leave it
out. Then:

1. Use an existing token; do not introduce a one-off duration.
2. Animate `transform`/`opacity` only.
3. Add the reduced-motion reset if you add a new keyframe.
4. If it conveys state, make sure text conveys it too.
