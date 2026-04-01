import { useState, useEffect, useRef } from 'react';
import type { ScanConfig, ScanResult, ScanEvent } from '../types';
import { connectScanWebSocket, startScan } from '../services/api';
import './ScanProgress.css';

interface ScanProgressProps {
  config: ScanConfig;
  onComplete: (result: ScanResult) => void;
  onBack: () => void;
}

const phaseLabels: Record<string, string> = {
  initializing: '⚙️ Initializing',
  subdomain_enumeration: '🌐 Subdomain Discovery',
  port_scanning: '🔓 Port Scanning',
  vulnerability_scanning: '🛡️ Vulnerability Scanning',
  osint_gathering: '🕵️ OSINT Intelligence',
  takeover_check: '⚠️ Takeover Detection',
  ai_analysis: '🤖 AI Analysis',
  reporting: '📊 Generating Report',
  completed: '✅ Complete',
};

const levelColors: Record<string, string> = {
  info: 'var(--blue)',
  success: 'var(--green)',
  warning: 'var(--yellow)',
  error: 'var(--red)',
  command: 'var(--text-muted)',
};

export default function ScanProgress({ config, onComplete, onBack }: ScanProgressProps) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('initializing');
  const [error, setError] = useState('');
  const [useFallback, setUseFallback] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Try WebSocket first
    let ws: WebSocket | null = null;
    const scanId = crypto.randomUUID().slice(0, 12);

    try {
      ws = connectScanWebSocket(
        scanId,
        config,
        (event) => {
          setEvents(prev => [...prev, event]);
          setProgress(event.progress);
          setCurrentPhase(event.phase);
        },
        (result) => {
          onComplete(result);
        },
        () => {
          // WebSocket failed, fall back to REST polling
          setUseFallback(true);
        }
      );
    } catch {
      setUseFallback(true);
    }

    return () => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    };
  }, [config, onComplete]);

  // Fallback: REST-based scan
  useEffect(() => {
    if (!useFallback) return;
    
    async function runViaRest() {
      try {
        setEvents(prev => [...prev, {
          phase: 'initializing', level: 'info',
          message: 'Starting scan via REST API...', progress: 5,
          timestamp: new Date().toISOString(),
        }]);

        const response = await startScan(config);
        
        setEvents(prev => [...prev, {
          phase: 'initializing', level: 'success',
          message: `Scan ${response.scan_id} started. Polling for results...`, progress: 10,
          timestamp: new Date().toISOString(),
        }]);

        // Poll for results
        const pollInterval = setInterval(async () => {
          try {
            const res = await fetch(`/api/scans/${response.scan_id}`);
            if (res.ok) {
              const data = await res.json();
              if (data.status === 'completed' || data.status === 'failed') {
                clearInterval(pollInterval);
                onComplete(data);
              } else {
                setProgress(prev => Math.min(prev + 5, 90));
                setCurrentPhase(data.status === 'analyzing' ? 'ai_analysis' : 'port_scanning');
              }
            }
          } catch { /* keep polling */ }
        }, 3000);

        return () => clearInterval(pollInterval);
      } catch (e) {
        setError(`Failed to start scan: ${e}`);
      }
    }
    runViaRest();
  }, [useFallback, config, onComplete]);

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [events]);

  return (
    <div className="scan-progress-page container animate-in">
      <button className="btn btn-secondary btn-sm" onClick={onBack} style={{ marginBottom: 24 }}>
        ← Cancel
      </button>

      <div className="progress-header">
        <h1>Scanning {config.target}</h1>
        <p className="progress-phase">{phaseLabels[currentPhase] || currentPhase}</p>
      </div>

      {error && (
        <div className="progress-error glass-card">
          <strong>Error:</strong> {error}
          <p style={{ marginTop: 8, fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Make sure the API server is running: <code>uvicorn reconbolt.api.app:app --reload</code>
          </p>
        </div>
      )}

      {/* Progress bar */}
      <div className="progress-bar-container glass-card">
        <div className="progress-bar-track">
          <div
            className="progress-bar-fill"
            style={{ width: `${Math.max(progress, 2)}%` }}
          ></div>
        </div>
        <div className="progress-percent">{Math.round(progress)}%</div>
      </div>

      {/* Phase indicators */}
      <div className="phase-indicators glass-card">
        {Object.entries(phaseLabels).map(([key, label]) => {
          const isCurrent = key === currentPhase;
          const isPast = Object.keys(phaseLabels).indexOf(key) < Object.keys(phaseLabels).indexOf(currentPhase);
          return (
            <div key={key} className={`phase-step ${isCurrent ? 'current' : ''} ${isPast ? 'done' : ''}`}>
              <span className="phase-dot"></span>
              <span className="phase-label">{label}</span>
            </div>
          );
        })}
      </div>

      {/* Live log */}
      <div className="log-panel glass-card">
        <div className="log-header">
          <span className="log-title">📟 Live Log</span>
          <span className="log-count">{events.length} events</span>
        </div>
        <div className="log-body" ref={logRef}>
          {events.map((event, i) => (
            <div key={i} className="log-line" style={{ animationDelay: `${i * 20}ms` }}>
              <span className="log-time">
                {new Date(event.timestamp).toLocaleTimeString()}
              </span>
              <span className="log-level" style={{ color: levelColors[event.level] || 'var(--text-secondary)' }}>
                [{event.level.toUpperCase()}]
              </span>
              <span className="log-msg">{event.message}</span>
            </div>
          ))}
          {events.length === 0 && !error && (
            <div className="log-line">
              <span className="log-msg" style={{ color: 'var(--text-muted)' }}>Connecting to scan server...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
