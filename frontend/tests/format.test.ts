import { describe, expect, it } from 'vitest';
import {
  SEVERITY_GLYPH,
  SEVERITY_ORDER,
  formatBytes,
  formatDuration,
  severityRank,
  titleCase,
  truncateMiddle,
} from '@/lib/format';

describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [512, '512 B'],
    [1024, '1.0 KB'],
    [20964, '20.5 KB'],
    [1048576, '1.0 MB'],
  ])('formats %i as %s', (input, expected) => {
    expect(formatBytes(input)).toBe(expected);
  });

  it('renders an em dash for a missing value', () => {
    expect(formatBytes(null)).toBe('—');
    expect(formatBytes(undefined)).toBe('—');
  });
});

describe('formatDuration', () => {
  it('uses milliseconds below one second', () => {
    expect(formatDuration(0.25)).toBe('250 ms');
  });

  it('uses seconds below a minute', () => {
    expect(formatDuration(2.468)).toBe('2.5 s');
  });

  it('uses minutes and seconds above a minute', () => {
    expect(formatDuration(125)).toBe('2m 5s');
  });

  it('renders an em dash for a missing value', () => {
    expect(formatDuration(null)).toBe('—');
  });
});

describe('severity helpers', () => {
  it('orders severities from most to least serious', () => {
    expect(SEVERITY_ORDER).toEqual(['critical', 'high', 'medium', 'low', 'info']);
  });

  it('ranks critical above info', () => {
    expect(severityRank('critical')).toBeGreaterThan(severityRank('info'));
  });

  it('gives every severity a distinct glyph, so colour is never the only signal', () => {
    const glyphs = SEVERITY_ORDER.map((severity) => SEVERITY_GLYPH[severity]);
    expect(new Set(glyphs).size).toBe(glyphs.length);
  });
});

describe('text helpers', () => {
  it('title cases a slug', () => {
    expect(titleCase('android-component-security')).toBe('Android Component Security');
  });

  it('truncates in the middle, keeping both ends visible', () => {
    const result = truncateMiddle('com/example/app/very/deep/path/Activity.java', 20);
    expect(result).toContain('…');
    expect(result.length).toBeLessThanOrEqual(21);
  });

  it('leaves short text untouched', () => {
    expect(truncateMiddle('short.java', 20)).toBe('short.java');
  });
});
