import { useState, useEffect } from 'react';
import type { ScanResult, ScanListItem } from '../types';
import { listScans, getScan, deleteScan } from '../services/api';
import './ScanHistory.css';

interface ScanHistoryProps {
  onViewResult: (result: ScanResult) => void;
  onBack: () => void;
}

export default function ScanHistory({ onViewResult, onBack }: ScanHistoryProps) {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadScans();
  }, []);

  async function loadScans() {
    setLoading(true);
    try {
      const data = await listScans();
      setScans(data);
    } catch (e) {
      setError('Cannot connect to API server. Make sure it is running.');
    } finally {
      setLoading(false);
    }
  }

  async function handleView(scanId: string) {
    try {
      const result = await getScan(scanId);
      onViewResult(result);
    } catch (e) {
      setError(`Failed to load scan: ${e}`);
    }
  }

  async function handleDelete(scanId: string) {
    try {
      await deleteScan(scanId);
      setScans(prev => prev.filter(s => s.scan_id !== scanId));
    } catch (e) {
      setError(`Failed to delete scan: ${e}`);
    }
  }

  return (
    <div className="history-page container animate-in">
      <button className="btn btn-secondary btn-sm" onClick={onBack} style={{ marginBottom: 24 }}>
        ← Back to Dashboard
      </button>

      <div className="history-header">
        <h1>📋 Scan History</h1>
        <p>View and manage your previous reconnaissance scans.</p>
      </div>

      {error && (
        <div className="history-error glass-card">
          <p>{error}</p>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 6 }}>
            Run: <code>cd reconbolt/backend && uvicorn reconbolt.api.app:app --reload</code>
          </p>
        </div>
      )}

      {loading ? (
        <div className="history-loading">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="skeleton-row skeleton" style={{ height: 56 }}></div>
          ))}
        </div>
      ) : scans.length === 0 ? (
        <div className="history-empty glass-card">
          <div className="empty-icon">🔍</div>
          <h3>No scans yet</h3>
          <p>Start your first scan to see results here.</p>
        </div>
      ) : (
        <div className="glass-card" style={{ overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Target</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Date</th>
                <th style={{ width: 140 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.scan_id}>
                  <td className="mono" style={{ fontSize: '0.82rem' }}>{scan.scan_id}</td>
                  <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{scan.target}</td>
                  <td>
                    <span className={`badge badge-${scan.status === 'completed' ? 'low' : scan.status === 'running' ? 'running' : 'high'}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${scan.risk_level}`}>
                      {scan.risk_score}/10 {scan.risk_level}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.82rem' }}>
                    {new Date(scan.started_at).toLocaleString()}
                  </td>
                  <td>
                    <div className="action-btns">
                      <button className="btn btn-primary btn-sm" onClick={() => handleView(scan.scan_id)}>
                        View
                      </button>
                      <button className="btn btn-danger btn-sm" onClick={() => handleDelete(scan.scan_id)}>
                        ✕
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
