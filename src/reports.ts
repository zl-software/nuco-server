// The reports store: a single Durable Object (idFromName('reports')) holding every
// abuse report submitted on this relay, so the operator can list and act on them (see
// PROTOCOL.md "Reports and bans"). A report is unverifiable policy input from a user:
// reporter and reported handle, a category, an optional comment. Never message content;
// everything between peers is sealed. One row per reporter and reported pair (a repeat
// report replaces the earlier one), which bounds storage alongside the REPORTS_MAX cap.
// Report rows are the only who to whom relationship the relay ever persists; they are
// never logged.

import { DurableObject } from 'cloudflare:workers';

import { intVar, type Env } from './env';

export type ReportRow = {
  id: number;
  reporter: string;
  reported: string;
  category: string;
  comment: string | null;
  context: string | null;
  created_at: number;
};

export type AddReportResult = { ok: true } | { ok: false; reason: 'full' };

export interface ReportInput {
  reporter: string;
  reported: string;
  category: string;
  comment?: string;
  context?: string;
}

export class ReportsDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter TEXT NOT NULL,
        reported TEXT NOT NULL,
        category TEXT NOT NULL,
        comment TEXT,
        context TEXT,
        created_at INTEGER NOT NULL,
        UNIQUE (reporter, reported)
      );
    `);
  }

  async add(report: ReportInput): Promise<AddReportResult> {
    const pairExists =
      this.ctx.storage.sql
        .exec('SELECT id FROM reports WHERE reporter = ? AND reported = ?', report.reporter, report.reported)
        .toArray().length > 0;
    if (!pairExists && this.count() >= intVar(this.env.REPORTS_MAX, 10000)) {
      return { ok: false, reason: 'full' };
    }
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO reports (reporter, reported, category, comment, context, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      report.reporter,
      report.reported,
      report.category,
      report.comment ?? null,
      report.context ?? null,
      Date.now(),
    );
    return { ok: true };
  }

  // Newest first, paged by id (pass the smallest id of the previous page as before).
  async list(limit: number, before?: number): Promise<ReportRow[]> {
    return this.ctx.storage.sql
      .exec<ReportRow>(
        'SELECT * FROM reports WHERE id < ? ORDER BY id DESC LIMIT ?',
        before ?? Number.MAX_SAFE_INTEGER,
        limit,
      )
      .toArray();
  }

  async remove(ids: number[]): Promise<number> {
    const before = this.count();
    for (const id of ids) {
      this.ctx.storage.sql.exec('DELETE FROM reports WHERE id = ?', id);
    }
    return before - this.count();
  }

  private count(): number {
    return Number(this.ctx.storage.sql.exec('SELECT COUNT(*) AS n FROM reports').one().n);
  }
}
