// In process token bucket rate limiter keyed by an arbitrary string (ip or handle).
// Sufficient for a single relay node. Horizontal scaling would move this to Redis.

interface Bucket {
  tokens: number;
  updated: number;
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly capacity: number;
  private readonly refillPerMs: number;

  constructor(maxPerMinute: number) {
    this.capacity = maxPerMinute;
    this.refillPerMs = maxPerMinute / 60000;
  }

  // Returns true if the action is allowed and consumes one token.
  allow(key: string, now: number): boolean {
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: this.capacity, updated: now };
      this.buckets.set(key, b);
    }
    const elapsed = now - b.updated;
    if (elapsed > 0) {
      b.tokens = Math.min(this.capacity, b.tokens + elapsed * this.refillPerMs);
      b.updated = now;
    }
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  // Drop idle buckets so the map does not grow unbounded.
  sweep(now: number): void {
    for (const [key, b] of this.buckets) {
      if (b.tokens >= this.capacity && now - b.updated > 300000) this.buckets.delete(key);
    }
  }
}
