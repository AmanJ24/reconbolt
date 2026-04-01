/* ========================================================================
   ReconBolt — API Client
   
   Uses relative URLs so the Vite dev proxy forwards to the backend.
   In production, configure the base URL via environment variable.
   ======================================================================== */

import type { ScanConfig, ScanResult, ScanListItem, ScanEvent } from '../types';

const API_BASE = '';  // Empty = relative URLs → routed by Vite proxy in dev

// --- REST API ---

export async function startScan(config: ScanConfig): Promise<{ scan_id: string; target: string; status: string }> {
  const res = await fetch(`${API_BASE}/api/scans/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Failed to start scan (${res.status}): ${detail}`);
  }
  return res.json();
}

export async function listScans(): Promise<ScanListItem[]> {
  const res = await fetch(`${API_BASE}/api/scans/`);
  if (!res.ok) throw new Error(`Failed to list scans: ${res.statusText}`);
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
  if (!res.ok) throw new Error(`Failed to get scan: ${res.statusText}`);
  return res.json();
}

export async function deleteScan(scanId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(`Failed to delete scan: ${res.statusText}`);
}

// --- WebSocket ---

export function connectScanWebSocket(
  scanId: string,
  config: ScanConfig,
  onEvent: (event: ScanEvent) => void,
  onComplete: (result: ScanResult) => void,
  onError: (error: string) => void,
): WebSocket {
  // Use the current page's host for WebSocket (works with Vite proxy)
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${wsProtocol}//${window.location.host}/api/scans/${scanId}/ws`;

  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    ws.send(JSON.stringify(config));
  };

  ws.onmessage = (event) => {
    try {
      const data: ScanEvent = JSON.parse(event.data);
      if (data.result) {
        onComplete(data.result);
      } else {
        onEvent(data);
      }
    } catch (e) {
      console.error('Failed to parse WebSocket message:', e);
    }
  };

  ws.onerror = () => {
    onError('WebSocket connection failed — is the backend running?');
  };

  ws.onclose = () => {
    // Connection closed
  };

  return ws;
}
