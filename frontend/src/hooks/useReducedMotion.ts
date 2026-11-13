import { useEffect, useState } from 'react';

/**
 * Tracks the user's reduced-motion preference.
 *
 * The CSS in `motion.css` already collapses every effect under the media
 * query. This hook exists for the cases CSS cannot cover — animated counters
 * and anything driven by JavaScript — which must jump to their final value
 * rather than tween.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return false;
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  });

  useEffect(() => {
    if (!window.matchMedia) return;
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = (event: MediaQueryListEvent) => setReduced(event.matches);
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  return reduced;
}
