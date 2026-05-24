import React, { useState, useEffect, useRef, useCallback } from 'react';
import * as d3 from 'd3';

// ─── Config ───────────────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  Critical: { color: '#ff3860', bg: 'rgba(255,56,96,0.15)',   border: '#ff3860' },
  High:     { color: '#ff8c42', bg: 'rgba(255,140,66,0.15)',  border: '#ff8c42' },
  Medium:   { color: '#ffd166', bg: 'rgba(255,209,102,0.15)', border: '#ffd166' },
  Low:      { color: '#06d6a0', bg: 'rgba(6,214,160,0.15)',   border: '#06d6a0' },
  Info:     { color: '#74b9ff', bg: 'rgba(116,185,255,0.15)', border: '#74b9ff' },
};

const PROFILES = ['passive', 'safe', 'balanced', 'aggressive', 'red_team'];

// ─── API helper ───────────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status} — ${res.statusText}`);
  return res.json();
}

// ─── Shared UI primitives ─────────────────────────────────────────────────────
function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.Info;
  return (
    <span style={{
      color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}`,
      padding: '2px 10px', borderRadius: 4, fontSize: 11, fontWeight: 700,
      letterSpacing: '0.06em', textTransform: 'uppercase', fontFamily: 'monospace',
    }}>
      {severity}
    </span>
  );
}

function StatCard({ icon, label, value, color, subtitle }) {
  return (
    <div
      style={{
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
        borderLeft: `3px solid ${color}`, borderRadius: 8, padding: '18px 22px',
        display: 'flex', flexDirection: 'column', gap: 4, transition: 'background 0.2s', cursor: 'default',
      }}
      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.06)'}
      onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <span style={{ fontSize: 18 }}>{icon}</span>
        <span style={{ color: '#8892a4', fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</span>
      </div>
      <div style={{ fontSize: 32, fontWeight: 800, color, lineHeight: 1, fontFamily: 'monospace' }}>{value}</div>
      {subtitle && <div style={{ color: '#555f6e', fontSize: 12, marginTop: 4 }}>{subtitle}</div>}
    </div>
  );
}

function ProgressBar({ value, color, height = 6 }) {
  return (
    <div style={{ background: 'rgba(255,255,255,0.08)', borderRadius: 99, overflow: 'hidden', height }}>
      <div style={{
        width: `${Math.min(100, Math.max(0, value))}%`, height: '100%', background: color,
        borderRadius: 99, transition: 'width 0.6s ease', boxShadow: `0 0 8px ${color}80`,
      }} />
    </div>
  );
}

function InputField({ value, onChange, placeholder, style = {} }) {
  return (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      style={{
        background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)',
        borderRadius: 6, padding: '9px 14px', color: '#e2e8f0', fontSize: 13,
        outline: 'none', width: '100%', fontFamily: 'monospace', ...style,
      }}
    />
  );
}

// ─── Panel wrapper ────────────────────────────────────────────────────────────
function Panel({ title, children, action }) {
  return (
    <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.02)' }}>
        <span style={{ color: '#e2e8f0', fontWeight: 700, fontSize: 14, letterSpacing: '0.04em' }}>{title}</span>
        {action}
      </div>
      <div style={{ padding: '18px 20px' }}>{children}</div>
    </div>
  );
}

// ─── Scan Launcher ────────────────────────────────────────────────────────────
function ScanLauncher({ activeScan, onScanStarted, onScanAborted }) {
  const [targets, setTargets]     = useState('');
  const [profile, setProfile]     = useState('safe');
  const [oos, setOos]             = useState('');
  const [exclusionsText, setExclusionsText] = useState('');
  const [parseSummary, setParseSummary] = useState('');
  const [auth, setAuth]           = useState('');
  const [launching, setLaunching] = useState(false);
  const [error, setError]         = useState('');

  const handleParseExclusions = async () => {
    const text = exclusionsText.trim() || oos.trim();
    if (!text) { setParseSummary(''); return; }
    try {
      const targetList = targets.split(',').map(t => t.trim()).filter(Boolean);
      const res = await apiFetch('/api/bugbounty/parse-exclusions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, in_scope: targetList }),
      });
      setOos(res.out_of_scope.join(', '));
      setParseSummary(res.summary || 'Parsed successfully');
    } catch (e) {
      setParseSummary(`Parse failed: ${e.message}`);
    }
  };

  const handleLaunch = async () => {
    const targetList = targets.split(',').map(t => t.trim()).filter(Boolean);
    if (!targetList.length) { setError('Enter at least one target (e.g. example.com)'); return; }
    setLaunching(true);
    setError('');
    try {
      const scan = await apiFetch('/api/scans/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets: targetList,
          profile,
          auth,
          out_of_scope: oos.split(',').map(s => s.trim()).filter(Boolean),
          exclusions_text: exclusionsText.trim() || oos.trim(),
        }),
      });
      setTargets('');
      onScanStarted(scan);
    } catch (e) {
      setError(e.message || 'Launch failed — is the QAYAMAT API running?');
    }
    setLaunching(false);
  };

  const isRunning = activeScan && activeScan.status === 'running';

  const handleCancel = async () => {
    if (!activeScan?.id) return;
    try {
      await apiFetch(`/api/scans/${activeScan.id}/cancel`, { method: 'POST' });
      onScanAborted();
    } catch (e) {
      setError(e.message || 'Cancel failed');
    }
  };

  const handlePause = async () => {
    if (!activeScan?.id) return;
    try {
      await apiFetch(`/api/scans/${activeScan.id}/pause`, { method: 'POST' });
      setError('');
    } catch (e) {
      setError(e.message || 'Pause failed');
    }
  };

  const handleResume = async () => {
    if (!activeScan?.id) return;
    try {
      await apiFetch(`/api/scans/${activeScan.id}/resume`, { method: 'POST' });
      setError('');
    } catch (e) {
      setError(e.message || 'Resume failed');
    }
  };

  const isPaused = activeScan && activeScan.status === 'paused';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Active scan banner */}
      {isRunning && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12,
          background: 'rgba(0,229,255,0.06)', border: '1px solid rgba(0,229,255,0.25)',
          borderRadius: 8, padding: '12px 16px',
        }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#00e5ff', boxShadow: '0 0 8px #00e5ff', flexShrink: 0, animation: 'pulse 1.5s infinite' }} />
          <div style={{ flex: 1 }}>
            <div style={{ color: '#00e5ff', fontWeight: 700, fontSize: 13 }}>Scan in progress — {activeScan.name}</div>
            <div style={{ color: '#8892a4', fontSize: 12, marginTop: 2 }}>Targets: {(activeScan.targets || []).join(', ')}</div>
          </div>
          <div style={{ color: '#00e5ff', fontFamily: 'monospace', fontWeight: 700 }}>{(activeScan.progress || 0).toFixed(0)}%</div>
          {!isPaused && (
            <button
              onClick={handlePause}
              style={{
                background: 'rgba(255,209,102,0.12)', border: '1px solid #ffd166',
                borderRadius: 6, color: '#ffd166', padding: '8px 16px', fontSize: 12,
                fontWeight: 700, cursor: 'pointer',
              }}
            >
              ⏸ Pause
            </button>
          )}
          {isPaused && (
            <button
              onClick={handleResume}
              style={{
                background: 'rgba(6,214,160,0.12)', border: '1px solid #06d6a0',
                borderRadius: 6, color: '#06d6a0', padding: '8px 16px', fontSize: 12,
                fontWeight: 700, cursor: 'pointer',
              }}
            >
              ▶ Resume
            </button>
          )}
          <button
            onClick={handleCancel}
            style={{
              background: 'rgba(255,56,96,0.15)', border: '1px solid #ff3860',
              borderRadius: 6, color: '#ff3860', padding: '8px 16px', fontSize: 12,
              fontWeight: 700, cursor: 'pointer',
            }}
          >
            ✕ Cancel
          </button>
        </div>
      )}

      {/* Target input */}
      <div>
        <label style={{ color: '#8892a4', fontSize: 12, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
          In-Scope Targets
        </label>
        <InputField
          value={targets}
          onChange={setTargets}
          placeholder="example.com, 192.168.1.0/24, *.staging.io  (comma-separated)"
        />
      </div>

      {/* Out-of-scope / intelligent exclusions */}
      <div>
        <label style={{ color: '#8892a4', fontSize: 12, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
          Exclusions <span style={{ color: '#444', fontWeight: 400, textTransform: 'none' }}>(paste policy text or comma-separated)</span>
        </label>
        <textarea
          value={exclusionsText}
          onChange={e => setExclusionsText(e.target.value)}
          placeholder={'Out of scope:\n*.staging.example.com\n/admin/*\nDo not test: denial of service, social engineering\nThird-party: payments.example.com'}
          rows={5}
          style={{
            background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)',
            borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 12,
            outline: 'none', width: '100%', fontFamily: 'monospace', resize: 'vertical',
          }}
        />
        <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
          <button
            type="button"
            onClick={handleParseExclusions}
            style={{
              background: 'rgba(0,229,255,0.1)', border: '1px solid rgba(0,229,255,0.35)',
              borderRadius: 6, color: '#00e5ff', padding: '6px 14px', fontSize: 12, cursor: 'pointer',
            }}
          >
            Parse exclusions
          </button>
          {parseSummary && <span style={{ color: '#06d6a0', fontSize: 11 }}>{parseSummary}</span>}
        </div>
        <InputField
          value={oos}
          onChange={setOos}
          placeholder="Parsed targets: staging.example.com, *.internal.io"
          style={{ marginTop: 8 }}
        />
      </div>

      {/* Auth + Profile row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 200px', gap: 12 }}>
        <div>
          <label style={{ color: '#8892a4', fontSize: 12, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
            Auth Cookie / Token <span style={{ color: '#444', fontWeight: 400, textTransform: 'none' }}>(optional)</span>
          </label>
          <InputField
            value={auth}
            onChange={setAuth}
            placeholder="session=abc123; token=bearer ..."
          />
        </div>
        <div>
          <label style={{ color: '#8892a4', fontSize: 12, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
            Profile
          </label>
          <select
            value={profile}
            onChange={e => setProfile(e.target.value)}
            style={{
              background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: 6, padding: '9px 14px', color: '#e2e8f0', fontSize: 13,
              outline: 'none', width: '100%', cursor: 'pointer',
            }}
          >
            {PROFILES.map(p => (
              <option key={p} value={p} style={{ background: '#0d1117' }}>{p}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Profile badge explanation */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {[
          { p: 'passive',    label: 'OSINT only — no active probing' },
          { p: 'safe',       label: 'Light active — safe for production' },
          { p: 'balanced',   label: 'Standard — includes PoC generation' },
          { p: 'aggressive', label: 'Full tools — not for prod' },
          { p: 'red_team',   label: 'Full exploitation — lab only' },
        ].map(({ p, label }) => (
          <div
            key={p}
            onClick={() => setProfile(p)}
            style={{
              padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
              border: `1px solid ${profile === p ? '#00e5ff' : 'rgba(255,255,255,0.08)'}`,
              background: profile === p ? 'rgba(0,229,255,0.1)' : 'transparent',
              color: profile === p ? '#00e5ff' : '#555f6e',
              fontSize: 11, transition: 'all 0.15s',
            }}
            title={label}
          >
            {p}
          </div>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div style={{ color: '#ff3860', fontSize: 12, background: 'rgba(255,56,96,0.08)', border: '1px solid rgba(255,56,96,0.25)', borderRadius: 6, padding: '10px 14px' }}>
          ⚠ {error}
        </div>
      )}

      {/* Launch button */}
      <div style={{ display: 'flex', gap: 10 }}>
        <button
          onClick={handleLaunch}
          disabled={launching || isRunning}
          style={{
            background: launching || isRunning ? 'rgba(0,229,255,0.05)' : 'rgba(0,229,255,0.15)',
            border: '1px solid #00e5ff',
            borderRadius: 7, color: launching || isRunning ? '#555' : '#00e5ff',
            padding: '11px 28px', fontSize: 14, fontWeight: 700,
            cursor: launching || isRunning ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s', letterSpacing: '0.05em',
          }}
        >
          {launching ? '⟳  Launching…' : isRunning ? '⟳  Scan Running…' : '▶  Launch Scan'}
        </button>

        <div style={{ color: '#555f6e', fontSize: 12, alignSelf: 'center', fontStyle: 'italic' }}>
          {isRunning
            ? 'Results update live in Findings & Assets tabs'
            : 'Scan runs fully in-process — results appear live on dashboard'}
        </div>
      </div>
    </div>
  );
}

// ─── Scan Monitor (real WebSocket, no fake animation) ─────────────────────────
function ScanMonitor({ scanId, activeScan }) {
  const [progress, setProgress] = useState(0);
  const [phase, setPhase]       = useState('');
  const [log, setLog]           = useState([]);
  const logRef = useRef(null);
  const wsRef  = useRef(null);

  useEffect(() => {
    if (!scanId) return;

    // Connect to scan-specific WS
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws/scan/${scanId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setLog(prev => [...prev.slice(-99), { time: ts(), msg: '⟳  Connected to live feed' }]);
    };

    ws.onmessage = e => {
      try {
        const data = JSON.parse(e.data);
        if (data.type === 'ping') return;

        // Progress / phase updates from pipeline
        if (data.progress !== undefined) setProgress(data.progress);
        if (data.phase)   setPhase(data.phase);
        if (data.message) setLog(prev => [...prev.slice(-99), { time: ts(), msg: data.message }]);

        // Init dump from WS connect
        if (data.type === 'init') {
          const s = data.scan;
          if (s) {
            setProgress(s.progress || 0);
            setPhase(s.status === 'complete' ? 'Scan complete' : s.status === 'running' ? 'Running…' : s.status || '');
          }
          if (Array.isArray(data.events)) {
            setLog(data.events.slice(-50).map(ev => ({ time: '', msg: ev.message || JSON.stringify(ev) })));
          }
        }

        if (data.type === 'complete') {
          setLog(prev => [...prev.slice(-99), { time: ts(), msg: `✓ Scan finished — ${data.findings_count || 0} findings` }]);
        }
        if (data.type === 'error') {
          setLog(prev => [...prev.slice(-99), { time: ts(), msg: `✗ ${data.message}` }]);
        }
      } catch {}
    };

    ws.onerror = () => setPhase('WebSocket error — check server');
    ws.onclose = () => setLog(prev => [...prev.slice(-99), { time: ts(), msg: '— Connection closed' }]);

    return () => { ws.close(); };
  }, [scanId]);

  // Sync progress from activeScan prop (polling fallback)
  useEffect(() => {
    if (!activeScan) return;
    setProgress(activeScan.progress || 0);
    if (activeScan.status === 'complete') setPhase('Scan complete');
    else if (activeScan.status === 'running') setPhase(phase || 'Running…');
    else if (activeScan.status === 'error') setPhase('Scan error');
  }, [activeScan]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  if (!scanId) {
    return (
      <div style={{ textAlign: 'center', padding: '40px 20px', color: '#444' }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>◎</div>
        <div style={{ color: '#555f6e', fontSize: 14 }}>No active scan</div>
        <div style={{ color: '#444', fontSize: 12, marginTop: 6 }}>
          Launch one using the form above — results will appear here and across all tabs in real time.
        </div>
      </div>
    );
  }

  const subPhases = [
    { name: 'Reconnaissance', pct: Math.min(100, progress * 2.5) },
    { name: 'Vuln Scanning',  pct: Math.max(0, (progress - 40) * 1.8) },
    { name: 'Reporting',      pct: Math.max(0, (progress - 90) * 10) },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ color: '#8892a4', fontSize: 13 }}>{phase || 'Connecting…'}</span>
        <span style={{ color: '#00e5ff', fontFamily: 'monospace', fontWeight: 700 }}>{progress.toFixed(1)}%</span>
      </div>

      <ProgressBar value={progress} color="#00e5ff" height={8} />

      {subPhases.map(ph => (
        <div key={ph.name} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ color: '#555f6e', fontSize: 12, width: 130, flexShrink: 0 }}>{ph.name}</span>
          <ProgressBar value={ph.pct} color="#7c3aed" height={4} />
          <span style={{ color: '#555f6e', fontSize: 11, fontFamily: 'monospace', width: 38, textAlign: 'right' }}>{ph.pct.toFixed(0)}%</span>
        </div>
      ))}

      {/* Live log */}
      <div
        ref={logRef}
        style={{
          background: '#090c10', border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: 6, padding: '10px 14px', height: 180, overflowY: 'auto',
          fontFamily: 'monospace', fontSize: 12, color: '#4ade80', lineHeight: 1.7,
        }}
      >
        {log.length === 0 && <span style={{ color: '#444' }}>Awaiting scan output…</span>}
        {log.map((entry, i) => (
          <div key={i}>
            {entry.time && <span style={{ color: '#444', userSelect: 'none' }}>[{entry.time}] </span>}
            <span>{entry.msg}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ts() { return new Date().toLocaleTimeString(); }

// ─── Findings Table ───────────────────────────────────────────────────────────
function FindingsTable({ findings }) {
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(null);

  const severities = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info'];
  const filtered = findings.filter(f => {
    const matchSev    = filter === 'All' || f.severity === filter;
    const matchSearch = !search || f.title.toLowerCase().includes(search.toLowerCase()) || f.url.toLowerCase().includes(search.toLowerCase());
    return matchSev && matchSearch;
  });

  return (
    <div>
      {/* Controls */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <InputField
          value={search}
          onChange={setSearch}
          placeholder="Search findings…"
          style={{ width: 220 }}
        />
        <div style={{ display: 'flex', gap: 6 }}>
          {severities.map(s => {
            const cfg    = SEVERITY_CONFIG[s];
            const active = filter === s;
            return (
              <button
                key={s}
                onClick={() => setFilter(s)}
                style={{
                  padding: '5px 12px', borderRadius: 5,
                  border: active ? `1px solid ${cfg?.color || '#00e5ff'}` : '1px solid rgba(255,255,255,0.1)',
                  background: active ? (cfg?.bg || 'rgba(0,229,255,0.15)') : 'transparent',
                  color: active ? (cfg?.color || '#00e5ff') : '#8892a4',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer', transition: 'all 0.15s',
                }}
              >
                {s}
              </button>
            );
          })}
        </div>
      </div>

      {/* Count */}
      <div style={{ color: '#555f6e', fontSize: 12, marginBottom: 10 }}>
        {filtered.length} finding{filtered.length !== 1 ? 's' : ''} {filter !== 'All' ? `(${filter})` : ''}
        {findings.length > filtered.length ? ` of ${findings.length} total` : ''}
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              {['#', 'Title', 'Severity', 'Type', 'URL'].map(h => (
                <th key={h} style={{ color: '#555f6e', fontWeight: 600, textAlign: 'left', padding: '8px 12px', textTransform: 'uppercase', fontSize: 11, letterSpacing: '0.06em' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => (
              <tr
                key={f.id}
                onClick={() => setSelected(selected?.id === f.id ? null : f)}
                style={{
                  borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer',
                  background: selected?.id === f.id ? 'rgba(0,229,255,0.06)' : 'transparent',
                  transition: 'background 0.15s',
                }}
                onMouseEnter={e => { if (selected?.id !== f.id) e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; }}
                onMouseLeave={e => { if (selected?.id !== f.id) e.currentTarget.style.background = 'transparent'; }}
              >
                <td style={{ padding: '10px 12px', color: '#444', fontFamily: 'monospace' }}>{i + 1}</td>
                <td style={{ padding: '10px 12px', color: '#e2e8f0', fontWeight: 500 }}>{f.title}</td>
                <td style={{ padding: '10px 12px' }}><SeverityBadge severity={f.severity} /></td>
                <td style={{ padding: '10px 12px', color: '#8892a4', fontFamily: 'monospace', fontSize: 12 }}>{f.vuln_type || '—'}</td>
                <td style={{ padding: '10px 12px', color: '#00e5ff', fontFamily: 'monospace', fontSize: 12, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.url}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} style={{ padding: '40px', textAlign: 'center', color: '#444' }}>
                  {findings.length === 0 ? 'No findings yet — run a scan to populate this table.' : 'No findings match the current filter.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Detail panel */}
      {selected && (
        <div style={{
          marginTop: 16, background: '#090c10',
          border: `1px solid ${SEVERITY_CONFIG[selected.severity]?.border || '#333'}`,
          borderRadius: 8, padding: '18px 22px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#e2e8f0', fontWeight: 700, fontSize: 15, marginBottom: 8 }}>{selected.title}</div>
              <SeverityBadge severity={selected.severity} />
            </div>
            <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: '#555', cursor: 'pointer', fontSize: 18 }}>✕</button>
          </div>
          <div style={{ marginTop: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div><span style={{ color: '#555f6e', fontSize: 12 }}>URL</span><div style={{ color: '#00e5ff', fontFamily: 'monospace', fontSize: 12, marginTop: 2, wordBreak: 'break-all' }}>{selected.url}</div></div>
            <div><span style={{ color: '#555f6e', fontSize: 12 }}>Type</span><div style={{ color: '#e2e8f0', fontFamily: 'monospace', fontSize: 12, marginTop: 2 }}>{selected.vuln_type || 'Unknown'}</div></div>
            <div><span style={{ color: '#555f6e', fontSize: 12 }}>Discovered</span><div style={{ color: '#e2e8f0', fontSize: 12, marginTop: 2 }}>{new Date(selected.created_at).toLocaleString()}</div></div>
            <div><span style={{ color: '#555f6e', fontSize: 12 }}>Tool</span><div style={{ color: '#e2e8f0', fontFamily: 'monospace', fontSize: 12, marginTop: 2 }}>{selected.tool || '—'}</div></div>
            {selected.description && (
              <div style={{ gridColumn: '1 / -1' }}>
                <span style={{ color: '#555f6e', fontSize: 12 }}>Description</span>
                <div style={{ color: '#c9d1d9', fontSize: 13, marginTop: 4, lineHeight: 1.6 }}>{selected.description}</div>
              </div>
            )}
            {selected.evidence && (
              <div style={{ gridColumn: '1 / -1' }}>
                <span style={{ color: '#555f6e', fontSize: 12 }}>Evidence</span>
                <pre style={{ color: '#4ade80', fontFamily: 'monospace', fontSize: 11, marginTop: 4, background: '#060810', padding: '10px', borderRadius: 4, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{selected.evidence}</pre>
              </div>
            )}
            {Array.isArray(selected.cve) && selected.cve.length > 0 && (
              <div>
                <span style={{ color: '#555f6e', fontSize: 12 }}>CVE</span>
                <div style={{ marginTop: 4, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {selected.cve.map(c => (
                    <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer"
                      style={{ color: '#ff8c42', fontFamily: 'monospace', fontSize: 11, textDecoration: 'none', background: 'rgba(255,140,66,0.1)', padding: '2px 8px', borderRadius: 3 }}>
                      {c}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Attack Graph (D3) ────────────────────────────────────────────────────────
function AttackGraph({ findings, assets }) {
  const svgRef = useRef(null);

  useEffect(() => {
    const el = svgRef.current;
    if (!el || (!findings.length && !assets.length)) return;
    const w = el.clientWidth || 700;
    const h = 340;

    d3.select(el).selectAll('*').remove();

    const svg = d3.select(el)
      .attr('viewBox', `0 0 ${w} ${h}`)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    svg.append('defs').append('marker')
      .attr('id', 'arrow').attr('viewBox', '0 -5 10 10')
      .attr('refX', 20).attr('refY', 0).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#00e5ff60');

    const nodes = [
      { id: 'attacker', label: '🔴 Attacker', type: 'attacker' },
      ...assets.slice(0, 5).map(a => ({ id: `asset_${a.id}`, label: a.url, type: 'asset' })),
      ...findings.filter(f => ['Critical', 'High'].includes(f.severity)).slice(0, 4).map(f => ({
        id: `finding_${f.id}`, label: f.vuln_type || f.severity, type: 'finding', severity: f.severity,
      })),
    ];

    const links = [];
    assets.slice(0, 5).forEach(a  => links.push({ source: 'attacker', target: `asset_${a.id}` }));
    findings.filter(f => ['Critical', 'High'].includes(f.severity)).slice(0, 4).forEach((f, i) => {
      const assetId = `asset_${assets[i % Math.max(assets.length, 1)]?.id || 1}`;
      links.push({ source: assetId, target: `finding_${f.id}` });
    });

    const simulation = d3.forceSimulation(nodes)
      .force('link',      d3.forceLink(links).id(d => d.id).distance(110))
      .force('charge',    d3.forceManyBody().strength(-250))
      .force('center',    d3.forceCenter(w / 2, h / 2))
      .force('collision', d3.forceCollide(38));

    const link = svg.append('g').selectAll('line').data(links).join('line')
      .attr('stroke', '#00e5ff30').attr('stroke-width', 1.5).attr('marker-end', 'url(#arrow)');

    const node = svg.append('g').selectAll('g').data(nodes).join('g')
      .call(d3.drag()
        .on('start', (ev, d) => { if (!ev.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
        .on('end',   (ev, d) => { if (!ev.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    node.append('circle')
      .attr('r', d => d.type === 'attacker' ? 22 : d.type === 'finding' ? 14 : 18)
      .attr('fill', d => {
        if (d.type === 'attacker') return 'rgba(255,56,96,0.2)';
        if (d.type === 'finding')  return SEVERITY_CONFIG[d.severity]?.bg || 'rgba(255,140,66,0.2)';
        return 'rgba(0,229,255,0.1)';
      })
      .attr('stroke', d => {
        if (d.type === 'attacker') return '#ff3860';
        if (d.type === 'finding')  return SEVERITY_CONFIG[d.severity]?.color || '#ff8c42';
        return '#00e5ff';
      })
      .attr('stroke-width', 1.5);

    node.append('text')
      .attr('text-anchor', 'middle').attr('dy', d => d.type === 'attacker' ? 36 : 30)
      .attr('fill', '#8892a4').attr('font-size', 10).attr('font-family', 'monospace')
      .text(d => d.label.length > 20 ? d.label.slice(0, 18) + '…' : d.label);

    simulation.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, [findings, assets]);

  if (!findings.length && !assets.length) {
    return (
      <div style={{ textAlign: 'center', padding: '60px 20px', color: '#444' }}>
        <div style={{ fontSize: 28, marginBottom: 8 }}>⬡</div>
        <div style={{ fontSize: 13 }}>Graph will populate after a scan is run.</div>
      </div>
    );
  }

  return (
    <div style={{ position: 'relative' }}>
      <svg ref={svgRef} style={{ width: '100%', height: 340, display: 'block' }} />
      <div style={{ position: 'absolute', bottom: 8, right: 8, display: 'flex', gap: 12, fontSize: 11, color: '#555f6e' }}>
        <span>🔴 Attacker</span><span style={{ color: '#00e5ff' }}>◉ Asset</span><span style={{ color: '#ff8c42' }}>◎ Finding</span>
        <span style={{ fontStyle: 'italic' }}>Drag nodes</span>
      </div>
    </div>
  );
}

// ─── Assets Panel ─────────────────────────────────────────────────────────────
function AssetsPanel({ assets }) {
  const [search, setSearch] = useState('');
  const typeColors = { domain: '#00e5ff', subdomain: '#7c3aed', ip: '#ff8c42', endpoint: '#06d6a0' };

  const filtered = assets.filter(a =>
    !search || a.url.toLowerCase().includes(search.toLowerCase()) ||
    (a.technologies || []).some(t => t.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <InputField value={search} onChange={setSearch} placeholder="Filter assets…" style={{ marginBottom: 4 }} />

      {filtered.length === 0 && (
        <div style={{ textAlign: 'center', padding: '40px', color: '#444' }}>
          {assets.length === 0 ? 'No assets yet — run a scan to discover them.' : 'No assets match the filter.'}
        </div>
      )}

      {filtered.map(a => (
        <div
          key={a.id}
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 14px', background: 'rgba(255,255,255,0.02)',
            border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, transition: 'background 0.15s',
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: typeColors[a.asset_type] || '#888',
              boxShadow: `0 0 6px ${typeColors[a.asset_type] || '#888'}`,
              flexShrink: 0,
            }} />
            <span style={{ color: '#e2e8f0', fontFamily: 'monospace', fontSize: 13 }}>{a.url}</span>
            {(a.open_ports || []).length > 0 && (
              <span style={{ color: '#555f6e', fontSize: 11, fontFamily: 'monospace' }}>
                [{a.open_ports.slice(0, 5).join(', ')}{a.open_ports.length > 5 ? '…' : ''}]
              </span>
            )}
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            {(a.technologies || []).slice(0, 3).map(t => (
              <span key={t} style={{
                background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 4, padding: '1px 7px', fontSize: 11, color: '#8892a4', fontFamily: 'monospace',
              }}>{t}</span>
            ))}
            <span style={{
              color: typeColors[a.asset_type] || '#888', fontSize: 11,
              textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.06em', marginLeft: 6,
            }}>{a.asset_type}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { id: 'dashboard', icon: '⬡', label: 'Dashboard' },
  { id: 'scan',      icon: '⟳', label: 'Launch / Monitor' },
  { id: 'findings',  icon: '⚑', label: 'Findings' },
  { id: 'assets',    icon: '◈', label: 'Assets' },
  { id: 'graph',     icon: '⬡', label: 'Attack Graph' },
  { id: 'reports',   icon: '▤', label: 'Reports' },
];

function Sidebar({ active, onNav, activeScan }) {
  return (
    <div style={{
      width: 220, background: '#060810', borderRight: '1px solid rgba(255,255,255,0.06)',
      display: 'flex', flexDirection: 'column', padding: '24px 0', flexShrink: 0,
    }}>
      <div style={{ padding: '0 20px 28px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ fontSize: 20, fontWeight: 900, color: '#ff3860', letterSpacing: '0.1em', fontFamily: 'monospace' }}>QAYAMAT</div>
        <div style={{ fontSize: 11, color: '#555f6e', marginTop: 4, letterSpacing: '0.05em' }}>Offensive Security OS</div>
      </div>

      {/* Scan status pill */}
      <div style={{ padding: '12px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {activeScan && activeScan.status === 'running' ? (
            <>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e5ff', boxShadow: '0 0 8px #00e5ff', animation: 'pulse 1.5s infinite' }} />
              <span style={{ color: '#00e5ff', fontSize: 12, fontWeight: 600 }}>Scan Running — {(activeScan.progress || 0).toFixed(0)}%</span>
            </>
          ) : activeScan && activeScan.status === 'complete' ? (
            <>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#06d6a0' }} />
              <span style={{ color: '#06d6a0', fontSize: 12, fontWeight: 600 }}>Last Scan Complete</span>
            </>
          ) : (
            <>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#555f6e' }} />
              <span style={{ color: '#555f6e', fontSize: 12 }}>No Active Scan</span>
            </>
          )}
        </div>
      </div>

      <nav style={{ flex: 1 }}>
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            onClick={() => onNav(item.id)}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 12,
              padding: '11px 20px',
              background: active === item.id ? 'rgba(0,229,255,0.08)' : 'transparent',
              borderLeft: active === item.id ? '2px solid #00e5ff' : '2px solid transparent',
              border: 'none', borderRight: 'none',
              color: active === item.id ? '#00e5ff' : '#8892a4',
              fontSize: 13, fontWeight: active === item.id ? 600 : 400,
              cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s',
            }}
            onMouseEnter={e => { if (active !== item.id) e.currentTarget.style.color = '#e2e8f0'; }}
            onMouseLeave={e => { if (active !== item.id) e.currentTarget.style.color = '#8892a4'; }}
          >
            <span style={{ fontFamily: 'monospace', fontSize: 14 }}>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <div style={{ padding: '16px 20px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ color: '#2a3140', fontSize: 11, fontFamily: 'monospace' }}>v1.0.0 — Pr0fessor_SnApe</div>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [activeNav,    setActiveNav]    = useState('dashboard');
  const [findings,     setFindings]     = useState([]);
  const [assets,       setAssets]       = useState([]);
  const [activeScan,   setActiveScan]   = useState(null);
  const [apiConnected, setApiConnected] = useState(false);
  const [loading,      setLoading]      = useState(true);
  const [lastUpdated,  setLastUpdated]  = useState(null);

  // ── Fetch real data from API ───────────────────────────────────────────────
  const refresh = useCallback(async () => {
    try {
      const [f, a, s] = await Promise.all([
        apiFetch('/api/findings'),
        apiFetch('/api/assets'),
        apiFetch('/api/scans/active'),
      ]);
      setFindings(Array.isArray(f) ? f : []);
      setAssets(Array.isArray(a) ? a : []);
      // active scan endpoint returns {status:'idle'} when nothing running
      setActiveScan(s && s.id ? s : null);
      setApiConnected(true);
      setLastUpdated(new Date());
    } catch {
      setApiConnected(false);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [refresh]);

  // ── Derived stats ──────────────────────────────────────────────────────────
  const critCount = findings.filter(f => f.severity === 'Critical').length;
  const highCount = findings.filter(f => f.severity === 'High').length;
  const medCount  = findings.filter(f => f.severity === 'Medium').length;

  // ── Page content ───────────────────────────────────────────────────────────
  const renderContent = () => {
    if (loading) {
      return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, gap: 12, color: '#555f6e' }}>
          <span style={{ fontSize: 20, animation: 'spin 1s linear infinite' }}>⟳</span>
          Connecting to QAYAMAT API…
        </div>
      );
    }

    switch (activeNav) {

      // ── Dashboard overview ────────────────────────────────────────────────
      case 'dashboard':
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* No-data banner */}
            {!apiConnected && (
              <div style={{ background: 'rgba(255,56,96,0.08)', border: '1px solid rgba(255,56,96,0.25)', borderRadius: 8, padding: '12px 16px', color: '#ff3860', fontSize: 13 }}>
                ⚠ Cannot reach the QAYAMAT API at <code style={{ fontFamily: 'monospace' }}>localhost:8000</code>. Start the server with <code style={{ fontFamily: 'monospace' }}>python3 qayamat.py</code> or <code style={{ fontFamily: 'monospace' }}>--dashboard-only</code>.
              </div>
            )}
            {apiConnected && findings.length === 0 && (
              <div style={{ background: 'rgba(0,229,255,0.05)', border: '1px solid rgba(0,229,255,0.15)', borderRadius: 8, padding: '12px 16px', color: '#8892a4', fontSize: 13 }}>
                ⬡ No scan data yet. Head to <strong style={{ color: '#00e5ff', cursor: 'pointer' }} onClick={() => setActiveNav('scan')}>Launch / Monitor</strong> to run your first scan.
              </div>
            )}

            {/* Stats row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
              <StatCard icon="⚑" label="Total Findings" value={findings.length} color="#00e5ff" subtitle={`${critCount} critical`} />
              <StatCard icon="🔴" label="Critical"       value={critCount}       color="#ff3860" subtitle="Immediate action" />
              <StatCard icon="🟠" label="High"           value={highCount}       color="#ff8c42" subtitle="High priority" />
              <StatCard icon="◈" label="Assets Found"   value={assets.length}   color="#7c3aed" subtitle="In scope" />
            </div>

            {/* Severity breakdown */}
            <Panel title="Severity Breakdown">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => {
                  const count = findings.filter(f => f.severity === sev).length;
                  const pct   = findings.length ? (count / findings.length) * 100 : 0;
                  return (
                    <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                      <span style={{ color: cfg.color, width: 64, fontSize: 13, fontWeight: 600 }}>{sev}</span>
                      <div style={{ flex: 1 }}><ProgressBar value={pct} color={cfg.color} height={6} /></div>
                      <span style={{ color: '#8892a4', fontFamily: 'monospace', fontSize: 12, width: 60, textAlign: 'right' }}>{count} ({pct.toFixed(0)}%)</span>
                    </div>
                  );
                })}
              </div>
            </Panel>

            {/* Two-col: scan monitor + recent findings */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <Panel title="Active Scan">
                <ScanMonitor scanId={activeScan?.id} activeScan={activeScan} />
              </Panel>
              <Panel title="Recent Findings">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {findings.length === 0 && <div style={{ color: '#444', fontSize: 13 }}>No findings yet.</div>}
                  {findings.slice(-5).reverse().map(f => (
                    <div key={f.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <span style={{ color: '#c9d1d9', fontSize: 13, flex: 1, marginRight: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                  ))}
                </div>
              </Panel>
            </div>

            {/* Attack graph */}
            <Panel
              title="Attack Graph"
              action={<button onClick={() => setActiveNav('graph')} style={{ background: 'rgba(0,229,255,0.1)', border: '1px solid #00e5ff40', borderRadius: 5, color: '#00e5ff', padding: '4px 12px', fontSize: 12, cursor: 'pointer' }}>Full View</button>}
            >
              <AttackGraph findings={findings} assets={assets} />
            </Panel>
          </div>
        );

      // ── Scan launcher + monitor ────────────────────────────────────────────
      case 'scan':
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <Panel title="⟳  Launch Scan">
              <ScanLauncher
                activeScan={activeScan}
                onScanStarted={scan => { setActiveScan(scan); refresh(); }}
                onScanAborted={() => refresh()}
              />
            </Panel>
            <Panel title="Live Scan Monitor">
              <ScanMonitor scanId={activeScan?.id} activeScan={activeScan} />
            </Panel>
          </div>
        );

      // ── Findings table ─────────────────────────────────────────────────────
      case 'findings':
        return (
          <Panel title={`Findings (${findings.length})`} action={
            <button onClick={refresh} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 5, color: '#8892a4', padding: '4px 12px', fontSize: 12, cursor: 'pointer' }}>↻ Refresh</button>
          }>
            <FindingsTable findings={findings} />
          </Panel>
        );

      // ── Assets ─────────────────────────────────────────────────────────────
      case 'assets':
        return (
          <Panel title={`Discovered Assets (${assets.length})`} action={
            <button onClick={refresh} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 5, color: '#8892a4', padding: '4px 12px', fontSize: 12, cursor: 'pointer' }}>↻ Refresh</button>
          }>
            <AssetsPanel assets={assets} />
          </Panel>
        );

      // ── Attack Graph ───────────────────────────────────────────────────────
      case 'graph':
        return (
          <Panel title="Attack Graph — Interactive">
            <AttackGraph findings={findings} assets={assets} />
          </Panel>
        );

      // ── Reports ────────────────────────────────────────────────────────────
      case 'reports':
        return (
          <Panel title="Reports">
            <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
              {[
                { label: 'Download JSON Report', href: '/api/reports/latest/json', color: '#00e5ff' },
                { label: 'Download HTML Report', href: '/api/reports/latest/html', color: '#7c3aed' },
              ].map(btn => (
                <a
                  key={btn.label}
                  href={btn.href}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: 'inline-block', background: 'rgba(255,255,255,0.04)',
                    border: `1px solid ${btn.color}40`, borderRadius: 6, color: btn.color,
                    padding: '9px 18px', fontSize: 13, fontWeight: 600, textDecoration: 'none',
                  }}
                >
                  {btn.label}
                </a>
              ))}
            </div>
            <div style={{ color: '#555f6e', fontSize: 13 }}>
              Reports are generated automatically after each completed scan and saved to the{' '}
              <code style={{ color: '#00e5ff', fontFamily: 'monospace' }}>reports/</code> directory.
              They are also available here for download after a scan completes.
            </div>
          </Panel>
        );

      default:
        return null;
    }
  };

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #080b12; color: #c9d1d9; font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #2a3140; border-radius: 99px; }
        @keyframes pulse  { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
        @keyframes spin   { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        select option { background: #0d1117; }
      `}</style>

      <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
        <Sidebar active={activeNav} onNav={setActiveNav} activeScan={activeScan} />

        <main style={{ flex: 1, overflowY: 'auto', padding: '28px 32px', animation: 'fadeIn 0.3s ease' }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
            <div>
              <h1 style={{ fontSize: 22, fontWeight: 800, color: '#e2e8f0', letterSpacing: '-0.02em' }}>
                {NAV_ITEMS.find(n => n.id === activeNav)?.label}
              </h1>
              <div style={{ color: '#555f6e', fontSize: 13, marginTop: 3 }}>
                {lastUpdated
                  ? `Updated ${lastUpdated.toLocaleTimeString()} — refreshes every 5s`
                  : new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 20, padding: '6px 14px',
              }}>
                <span style={{
                  width: 7, height: 7, borderRadius: '50%',
                  background: apiConnected ? '#06d6a0' : '#ff3860',
                  boxShadow: apiConnected ? '0 0 8px #06d6a0' : '0 0 8px #ff3860',
                }} />
                <span style={{ color: '#8892a4', fontSize: 12 }}>
                  {apiConnected ? 'API Connected' : 'API Disconnected'}
                </span>
              </div>
            </div>
          </div>

          {/* Page body */}
          <div key={activeNav} style={{ animation: 'fadeIn 0.25s ease' }}>
            {renderContent()}
          </div>
        </main>
      </div>
    </>
  );
}
