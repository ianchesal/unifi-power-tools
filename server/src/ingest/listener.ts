import dgram from 'node:dgram';
import { type EventsWriter, insertEvent } from '../db/eventsDb.js';
import { parseMessage } from './parser/index.js';

export interface SyslogListener {
  droppedCount(): number;
  // True once bound; false after a socket error or close.
  bound(): boolean;
  close(): Promise<void>;
}

export interface SyslogListenerOptions {
  port: number;
  bindAddress: string;
  maxMessageBytes: number;
  // Kernel receive buffer for the UDP socket. A bigger buffer rides out the
  // event loop being blocked by a synchronous analysis run.
  recvBufferSize?: number;
  log?: (message: string) => void;
}

export function startSyslogListener(
  db: EventsWriter,
  options: SyslogListenerOptions
): Promise<SyslogListener> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let dropped = 0;
    let isBound = false;

    socket.on('message', (msg) => {
      if (msg.byteLength > options.maxMessageBytes) {
        dropped += 1;
        return;
      }
      try {
        const raw = msg.toString('utf8');
        const event = parseMessage(raw);
        insertEvent(db, event);
      } catch {
        // Never let a parse/insert failure (e.g. transient SQLite lock
        // contention) escape the socket's 'message' handler and crash
        // the process. This service must keep listening.
      }
    });

    socket.once('error', reject);

    socket.bind(options.port, options.bindAddress, () => {
      socket.removeListener('error', reject);
      isBound = true;
      if (options.recvBufferSize) socket.setRecvBufferSize(options.recvBufferSize);
      // Register a permanent, non-throwing error handler so a runtime
      // socket error (e.g. ECONNRESET from an ICMP port-unreachable)
      // never becomes an unhandled EventEmitter error and crashes the
      // process. The socket may no longer be usable, so report it as
      // unbound (health shows it) and log once.
      socket.on('error', (err) => {
        if (isBound) options.log?.(`Syslog listener socket error: ${err.message}`);
        isBound = false;
      });
      socket.on('close', () => {
        isBound = false;
      });
      resolve({
        droppedCount: () => dropped,
        bound: () => isBound,
        close: () => new Promise<void>((res) => socket.close(() => res())),
      });
    });
  });
}
