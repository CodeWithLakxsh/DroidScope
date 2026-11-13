/** Formatting helpers shared across views. */

import type { Severity } from '@/types/api';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Severity is communicated by glyph + label + colour, never colour alone.
 * These glyphs match the ones used in the PDF and CLI output.
 */
export const SEVERITY_GLYPH: Record<Severity, string> = {
  critical: '◆',
  high: '▲',
  medium: '■',
  low: '●',
  info: '·',
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(severity);
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '—';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value.toFixed(exponent === 0 ? 0 : value >= 100 ? 0 : 1)} ${units[exponent]}`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—';
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m ${remainder}s`;
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const deltaSeconds = (Date.now() - date.getTime()) / 1000;
  const units: [number, Intl.RelativeTimeFormatUnit][] = [
    [60, 'second'],
    [3600, 'minute'],
    [86400, 'hour'],
    [2592000, 'day'],
  ];
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  if (deltaSeconds < 60) return formatter.format(-Math.round(deltaSeconds), 'second');
  for (let index = 1; index < units.length; index += 1) {
    const [limit, unit] = units[index];
    if (deltaSeconds < limit) {
      const divisor = units[index - 1][0];
      return formatter.format(-Math.round(deltaSeconds / divisor), unit);
    }
  }
  return formatDateTime(value);
}

export function truncateMiddle(text: string, max = 48): string {
  if (text.length <= max) return text;
  const half = Math.floor((max - 1) / 2);
  return `${text.slice(0, half)}…${text.slice(text.length - half)}`;
}

export function titleCase(text: string): string {
  return text
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

export function shortId(id: string | null | undefined, length = 8): string {
  return id ? id.slice(0, length) : '—';
}
