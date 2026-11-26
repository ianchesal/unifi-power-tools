import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import dgram from 'node:dgram';
import { openEventsWriter, type EventsWriter } from '../../src/db/eventsDb.js';
import { startSyslogListener, type SyslogListener } from '../../src/ingest/listener.js';

let dir: string;
let db: EventsWriter;
let listener: SyslogListener;
const PORT = 31514;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'upt-test-'));
  db = openEventsWriter(join(dir, 'events.db'));
  listener = await startSyslogListener(db, { port: PORT, bindAddress: '127.0.0.1', maxMessageBytes: 100 });
});

afterEach(async () => {
  await listener.close();
  db.close();
  await rm(dir, { recursive: true, force: true });
});

function sendUdp(message: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const client = dgram.createSocket('udp4');
    client.send(message, PORT, '127.0.0.1', (err) => {
      client.close();
      if (err) reject(err);
      else resolve();
    });
  });
}

function waitFor(predicate: () => boolean, timeoutMs = 2000): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      if (predicate()) return resolve();
      if (Date.now() - start > timeoutMs) return reject(new Error('timed out waiting for condition'));
      setTimeout(check, 20);
    };
    check();
  });
}

describe('startSyslogListener', () => {
  it('parses and stores a valid incoming message', async () => {
    await sendUdp('CEF:0|Ubiquiti|UniFi Network|9.3.33|1|Test|1|msg=hello');
    await waitFor(() => {
      const row = db.conn.prepare('SELECT COUNT(*) as count FROM events').get() as { count: number };
      return row.count === 1;
    });
    const row = db.conn.prepare('SELECT * FROM events').get() as { parsed: number };
    expect(row.parsed).toBe(1);
  });

  it('drops oversized messages without storing them', async () => {
    const oversized = 'x'.repeat(200);
    await sendUdp(oversized);
    await waitFor(() => listener.droppedCount() === 1);
    const row = db.conn.prepare('SELECT COUNT(*) as count FROM events').get() as { count: number };
    expect(row.count).toBe(0);
  });

  it('stores an unparsed row for malformed input rather than dropping it', async () => {
    await sendUdp('not a cef message at all');
    await waitFor(() => {
      const row = db.conn.prepare('SELECT COUNT(*) as count FROM events').get() as { count: number };
      return row.count === 1;
    });
    const row = db.conn.prepare('SELECT * FROM events').get() as { parsed: number };
    expect(row.parsed).toBe(0);
  });

  it('does not crash the process when insertEvent throws (e.g. a closed db)', async () => {
    let caught: unknown = null;
    const onUncaught = (err: unknown) => {
      caught = err;
    };
    process.on('uncaughtException', onUncaught);
    try {
      // Close the db underlying this listener so insertEvent throws
      // synchronously when the next message arrives.
      db.close();
      await sendUdp('CEF:0|Ubiquiti|UniFi Network|9.3.33|1|Test|1|msg=hello');
      // Give the event loop a moment to deliver the datagram and run
      // (and fail) the insert attempt.
      await new Promise((resolve) => setTimeout(resolve, 200));
    } finally {
      process.removeListener('uncaughtException', onUncaught);
    }
    expect(caught).toBeNull();
  });

  it('does not crash the process on a runtime socket error', async () => {
    const createSocketSpy = vi.spyOn(dgram, 'createSocket');
    const otherDb = await (async () => {
      const otherDir = await mkdtemp(join(tmpdir(), 'upt-test-'));
      return { dir: otherDir, db: openEventsWriter(join(otherDir, 'events.db')) };
    })();
    const otherListener = await startSyslogListener(otherDb.db, {
      port: PORT + 1,
      bindAddress: '127.0.0.1',
      maxMessageBytes: 100,
    });
    const socket = createSocketSpy.mock.results[createSocketSpy.mock.results.length - 1]
      .value as dgram.Socket;
    createSocketSpy.mockRestore();

    let caught: unknown = null;
    const onUncaught = (err: unknown) => {
      caught = err;
    };
    process.on('uncaughtException', onUncaught);
    try {
      // Simulate a runtime socket error (e.g. ECONNRESET from an ICMP
      // port-unreachable). With zero error listeners registered after
      // bind, this would be an unhandled 'error' event and crash the
      // process synchronously.
      socket.emit('error', new Error('simulated runtime socket error'));
    } finally {
      process.removeListener('uncaughtException', onUncaught);
    }
    expect(caught).toBeNull();

    await otherListener.close();
    otherDb.db.close();
    await rm(otherDb.dir, { recursive: true, force: true });
  });

  it('reports bound() true after bind and false after a socket error', async () => {
    expect(listener.bound()).toBe(true);
    const createSocketSpy = vi.spyOn(dgram, 'createSocket');
    const other = await startSyslogListener(db, { port: PORT + 2, bindAddress: '127.0.0.1', maxMessageBytes: 100 });
    const socket = createSocketSpy.mock.results[createSocketSpy.mock.results.length - 1].value as dgram.Socket;
    createSocketSpy.mockRestore();
    expect(other.bound()).toBe(true);
    socket.emit('error', new Error('simulated'));
    expect(other.bound()).toBe(false);
    await other.close();
  });

  it('reports bound() false after close', async () => {
    const other = await startSyslogListener(db, { port: PORT + 3, bindAddress: '127.0.0.1', maxMessageBytes: 100 });
    await other.close();
    expect(other.bound()).toBe(false);
  });

  it('survives a binary garbage datagram and still stores the next valid one', async () => {
    await new Promise<void>((resolve, reject) => {
      const client = dgram.createSocket('udp4');
      client.send(Buffer.from([0xff, 0x00, 0xfe]), PORT, '127.0.0.1', (err) => {
        client.close();
        if (err) reject(err);
        else resolve();
      });
    });
    await sendUdp('CEF:0|Ubiquiti|UniFi Network|9.3.33|1|Test|1|msg=after-garbage');
    await waitFor(() => {
      const rows = db.conn.prepare("SELECT raw FROM events").all() as { raw: string }[];
      return rows.some((r) => r.raw.includes('after-garbage'));
    });
  });

  it('rejects when the port is already in use', async () => {
    await expect(
      startSyslogListener(db, { port: PORT, bindAddress: '127.0.0.1', maxMessageBytes: 100 })
    ).rejects.toThrow();
  });

  it('raises the receive buffer when recvBufferSize is given', async () => {
    const createSocketSpy = vi.spyOn(dgram, 'createSocket');
    const plain = await startSyslogListener(db, { port: PORT + 4, bindAddress: '127.0.0.1', maxMessageBytes: 100 });
    const raised = await startSyslogListener(db, {
      port: PORT + 5, bindAddress: '127.0.0.1', maxMessageBytes: 100, recvBufferSize: 4 * 1024 * 1024,
    });
    const sockets = createSocketSpy.mock.results.slice(-2).map((r) => r.value as dgram.Socket);
    createSocketSpy.mockRestore();
    // The kernel caps the size (Linux: net.core.rmem_max), so only assert it went up.
    expect(sockets[1].getRecvBufferSize()).toBeGreaterThan(sockets[0].getRecvBufferSize());
    await plain.close();
    await raised.close();
  });
});
