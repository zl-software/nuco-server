// Test helper: boots the Workers relay locally via wrangler dev (real workerd, real
// Durable Objects) with fresh state per run, and tears it down afterwards.

import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface DevServer {
  port: number;
  httpUrl: string;
  wsUrl: string;
  stop(): void;
}

export async function startDevServer(port: number, extraVars: Record<string, string> = {}): Promise<DevServer> {
  const vars: Record<string, string> = { DEV: '1', ...extraVars };
  const args = ['wrangler', 'dev', '--port', String(port), '--persist-to', mkdtempSync(join(tmpdir(), 'nuco-relay-test-'))];
  for (const [k, v] of Object.entries(vars)) args.push('--var', `${k}:${v}`);
  const child = spawn('npx', args, {
    cwd: join(dirname(fileURLToPath(import.meta.url)), '..'),
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  let output = '';
  child.stdout?.on('data', (d: Buffer) => (output += d.toString()));
  child.stderr?.on('data', (d: Buffer) => (output += d.toString()));

  const httpUrl = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      const res = await fetch(`${httpUrl}/health`);
      if (res.ok) break;
    } catch {
      // Not up yet.
    }
    if (Date.now() > deadline) {
      child.kill('SIGTERM');
      throw new Error(`wrangler dev did not become healthy on ${port}:\n${output.slice(-2000)}`);
    }
    await new Promise((r) => setTimeout(r, 250));
  }

  return {
    port,
    httpUrl,
    wsUrl: `ws://127.0.0.1:${port}`,
    stop() {
      // wrangler spawns workerd as a child; kill the whole process group.
      try {
        if (child.pid) process.kill(-child.pid, 'SIGTERM');
      } catch {
        child.kill('SIGTERM');
      }
    },
  };
}

export async function debugState(server: DevServer, handle: string): Promise<{ queueDepth: number; wakes: number }> {
  const res = await fetch(`${server.httpUrl}/debug/state?handle=${encodeURIComponent(handle)}`);
  if (!res.ok) throw new Error(`debug state failed: ${res.status}`);
  return (await res.json()) as { queueDepth: number; wakes: number };
}
