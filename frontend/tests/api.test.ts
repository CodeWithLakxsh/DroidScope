import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from '@/lib/api';

function mockFetch(body: unknown, init: { status?: number } = {}) {
  // A fresh Response per call: a body can only be consumed once, so a shared
  // instance would make the second call in a test see an empty body.
  const spy = vi.fn().mockImplementation(
    async () =>
      new Response(JSON.stringify(body), {
        status: init.status ?? 200,
        headers: { 'Content-Type': 'application/json' },
      }),
  );
  globalThis.fetch = spy as never;
  return spy;
}

afterEach(() => vi.restoreAllMocks());

describe('api client', () => {
  it('requests the health endpoint', async () => {
    const spy = mockFetch({ status: 'ok', database: true, version: '0.1.0', queue_pending: 0 });
    const result = await api.health();
    expect(result.status).toBe('ok');
    expect(spy).toHaveBeenCalledWith('/api/v1/health', expect.anything());
  });

  it('serialises array filters as repeated query parameters', async () => {
    const spy = mockFetch({ items: [], total: 0, limit: 50, offset: 0 });
    await api.listFindings('scan1', { severity: ['critical', 'high'] });
    const url = spy.mock.calls[0][0] as string;
    expect(url).toContain('severity=critical');
    expect(url).toContain('severity=high');
  });

  it('omits empty filter values', async () => {
    const spy = mockFetch({ items: [], total: 0, limit: 50, offset: 0 });
    await api.listFindings('scan1', { search: '', category: undefined });
    const url = spy.mock.calls[0][0] as string;
    expect(url).not.toContain('search=');
    expect(url).not.toContain('category=');
  });

  it('turns a structured server error into an ApiError', async () => {
    mockFetch(
      { error: { code: 'apk_validation_error', message: 'file is not a ZIP archive', details: {} } },
      { status: 400 },
    );
    await expect(api.getApk('missing')).rejects.toBeInstanceOf(ApiError);
    try {
      await api.getApk('missing');
    } catch (error) {
      expect((error as ApiError).code).toBe('apk_validation_error');
      expect((error as ApiError).status).toBe(400);
      expect((error as ApiError).message).toBe('file is not a ZIP archive');
    }
  });

  it('falls back to the status text when the body is not JSON', async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(new Response('<html>502</html>', { status: 502 })) as never;
    await expect(api.health()).rejects.toMatchObject({ status: 502 });
  });

  it('builds a download URL without fetching', () => {
    expect(api.reportDownloadUrl('abc')).toBe('/api/v1/reports/abc/download');
  });
});
