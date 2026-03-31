/* ========================================================================
   ReconBolt — API Client
   ======================================================================== */

import type { ScanConfig, ScanResult, ScanListItem, ScanEvent } from '../types';

const API_BASE = 'http://localhost:8000';

// --- REST API ---

export async function startScan(config: ScanConfig): Promise<{ scan_id: string; target: string; status: string }> {
  const res = await fetch(`${API_BASE}/api/scans/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  if (!res.ok) throw new Error(`Failed to start scan: ${res.statusText}`);
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
  const ws = new WebSocket(`ws://localhost:8000/api/scans/${scanId}/ws`);

  ws.onopen = () => {
    ws.send(JSON.stringify(config));
  };

  ws.onmessage = (event) => {
    const data: ScanEvent = JSON.parse(event.data);
    if (data.result) {
      onComplete(data.result);
    } else {
      onEvent(data);
    }
  };

  ws.onerror = () => {
    onError('WebSocket connection failed');
  };

  ws.onclose = () => {
    // Connection closed
  };

  return ws;
}
