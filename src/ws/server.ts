// The relay WebSocket server: connection lifecycle, the live socket registry, heartbeat,
// and the expiry sweep. Wires the storage and push layers to the message handlers.

import { WebSocketServer } from 'ws';
import type { Server as HttpServer } from 'node:http';

import type { Config } from '../config.js';
import type { Storage, DeviceRecord } from '../storage/interface.js';
import type { PushFanout } from '../push/sender.js';
import { RateLimiter } from '../ratelimit.js';
import { Session } from './session.js';
import { handleRawMessage, type RelayContext } from './handlers.js';

const HEARTBEAT_MS = 30000;
const SWEEP_MS = 3600000;

export class RelayServer implements RelayContext {
  private wss: WebSocketServer | null = null;
  private readonly connections = new Map<string, Session>();
  private readonly sessions = new Set<Session>();
  private readonly rate: RateLimiter;
  private heartbeat: ReturnType<typeof setInterval> | null = null;
  private sweepTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    public readonly config: Config,
    public readonly storage: Storage,
    private readonly fanout: PushFanout,
  ) {
    this.rate = new RateLimiter(config.rateMaxPerMin);
  }

  attach(server: HttpServer): void {
    this.wss = new WebSocketServer({ server, maxPayload: this.config.maxMessageBytes + 8192 });
    this.wss.on('connection', (ws, req) => {
      const ip = (req.socket.remoteAddress ?? 'unknown').toString();
      if (this.config.dev) console.log(`[relay] socket connected from ${ip}`);
      const session = new Session(ws, ip);
      this.sessions.add(session);
      ws.on('message', (data, isBinary) => {
        if (isBinary) {
          ws.close();
          return;
        }
        handleRawMessage(this, session, data.toString());
      });
      ws.on('pong', () => {
        session.alive = true;
      });
      ws.on('close', () => {
        if (this.config.dev) console.log(`[relay] socket closed from ${ip}`);
        this.sessions.delete(session);
        this.unbind(session);
      });
      ws.on('error', () => {
        try {
          ws.terminate();
        } catch {
          // ignore
        }
      });
    });
    this.startHeartbeat();
    this.startSweep();
  }

  // --- RelayContext ---

  now(): number {
    return Date.now();
  }

  rateAllow(key: string): boolean {
    return this.rate.allow(key, Date.now());
  }

  bind(handle: string, session: Session): void {
    const prev = this.connections.get(handle);
    if (prev && prev !== session) {
      try {
        prev.ws.close();
      } catch {
        // ignore
      }
    }
    this.connections.set(handle, session);
  }

  unbind(session: Session): void {
    if (session.handle && this.connections.get(session.handle) === session) {
      this.connections.delete(session.handle);
    }
  }

  liveSession(handle: string): Session | undefined {
    const s = this.connections.get(handle);
    return s && s.authenticated ? s : undefined;
  }

  wake(device: DeviceRecord): void {
    this.fanout.wake(device).catch((err) => console.error('[relay] push wake failed', err));
  }

  // --- lifecycle ---

  private startHeartbeat(): void {
    this.heartbeat = setInterval(() => {
      for (const session of this.sessions) {
        if (!session.alive) {
          try {
            session.ws.terminate();
          } catch {
            // ignore
          }
          this.sessions.delete(session);
          this.unbind(session);
          continue;
        }
        session.alive = false;
        try {
          session.ws.ping();
        } catch {
          // ignore
        }
      }
      this.rate.sweep(Date.now());
    }, HEARTBEAT_MS);
    this.heartbeat.unref?.();
  }

  private startSweep(): void {
    this.sweepTimer = setInterval(() => {
      const removed = this.storage.deleteExpired(this.config.queueTtlSeconds, Date.now());
      if (removed > 0) console.log(`[relay] swept ${removed} expired queued messages`);
    }, SWEEP_MS);
    this.sweepTimer.unref?.();
  }

  close(): void {
    if (this.heartbeat) clearInterval(this.heartbeat);
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    this.wss?.close();
  }
}
