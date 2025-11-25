import { io, Socket } from 'socket.io-client';
import { getToken } from './auth';

// Singleton Socket.IO client used across the frontend for real-time updates
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

let socket: Socket | null = null;

export function getSocket(): Socket {
  if (!socket) {
    const token = typeof window !== 'undefined' ? getToken() : null;

    // Allow Socket.IO to negotiate transports (polling/websocket)
    socket = io(API_URL, {
      path: '/socket.io',
      auth: token ? { token } : undefined,
    });
  }
  return socket;
}

export default getSocket;
