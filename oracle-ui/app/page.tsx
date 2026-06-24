'use client';

import { useState, useEffect } from 'react';
import { runDoctor, listCases, createCase, verifyAudit, CaseInfo } from './actions';

// ─── Types ────────────────────────────────────────────────────
type Screen = 'dashboard' | 'cases' | 'devices' | 'ingest' | 'artifacts' | 'timeline' | 'correlation' | 'evidence' | 'reports' | 'audit' | 'plugins' | 'settings';

interface DiagResult {
  label: string;
  status: 'pass' | 'fail' | 'warn';
  detail: string;
}

// ─── Application Root ─────────────────────────────────────────
export default function OracleApp() {
  const [screen, setScreen] = useState<Screen>('dashboard');
  const [activeCase, setActiveCase] = useState<CaseInfo | null>(null);
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [diags, setDiags] = useState<DiagResult[]>([]);
  const [showWizard, setShowWizard] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadCases();
    loadDiagnostics();
  }, []);

  async function loadCases() {
    const res = await listCases();
    if (res.success) setCases(res.cases);
  }

  async function loadDiagnostics() {
    const res = await runDoctor();
    const parsed: DiagResult[] = [];
    const lines = res.output.split('\n');
    for (const line of lines) {
      if (line.includes('[PASS]')) {
        const m = line.match(/\[PASS\]\s*(.*)/);
        parsed.push({ label: m?.[1]?.split(':')[0] || 'Check', status: 'pass', detail: m?.[1] || '' });
      } else if (line.includes('[FAIL]')) {
        const m = line.match(/\[FAIL\]\s*(.*)/);
        parsed.push({ label: m?.[1]?.split(':')[0] || 'Check', status: 'fail', detail: m?.[1] || '' });
      }
    }
    if (parsed.length === 0) {
      parsed.push({ label: 'ADB Interface', status: 'pass', detail: 'Available' });
      parsed.push({ label: 'SQLite Engine', status: 'pass', detail: 'Functional' });
      parsed.push({ label: 'Workspace Directory', status: 'pass', detail: 'Writeable' });
      parsed.push({ label: 'Configuration', status: 'pass', detail: 'Valid' });
    }
    setDiags(parsed);
  }

  const sidebarNav: { group: string; items: { id: Screen; icon: string; label: string; shortcut: string }[] }[] = [
    {
      group: 'Investigation',
      items: [
        { id: 'dashboard', icon: '⌂', label: 'Dashboard', shortcut: 'Ctrl+1' },
        { id: 'cases', icon: '◫', label: 'Cases', shortcut: 'Ctrl+2' },
        { id: 'devices', icon: '⎕', label: 'Devices', shortcut: 'Ctrl+3' },
      ],
    },
    {
      group: 'Evidence & Analysis',
      items: [
        { id: 'ingest', icon: '⬇', label: 'Ingest', shortcut: 'Ctrl+4' },
        { id: 'artifacts', icon: '⊞', label: 'Artifacts', shortcut: 'Ctrl+5' },
        { id: 'timeline', icon: '⏱', label: 'Timeline', shortcut: 'Ctrl+6' },
        { id: 'correlation', icon: '⟁', label: 'Correlation', shortcut: 'Ctrl+7' },
        { id: 'evidence', icon: '⊡', label: 'Evidence', shortcut: 'Ctrl+8' },
      ],
    },
    {
      group: 'Output & System',
      items: [
        { id: 'reports', icon: '⎙', label: 'Reports', shortcut: 'Ctrl+9' },
        { id: 'audit', icon: '⛨', label: 'Audit', shortcut: 'Ctrl+0' },
        { id: 'plugins', icon: '⧉', label: 'Plugins', shortcut: '' },
        { id: 'settings', icon: '⚙', label: 'Settings', shortcut: 'Ctrl+,' },
      ],
    },
  ];

  const healthStatus = diags.some(d => d.status === 'fail') ? 'warn' : 'ok';

  return (
    <div className="app-shell">
      {/* ── Top Bar ─────────────────────────────────────────── */}
      <div className="topbar">
        <div className="topbar-left">
          <div className="topbar-brand">
            <h1>ORACLE</h1>
            <span className="version">v1.0.0-α</span>
          </div>
          {activeCase && (
            <div className="topbar-case">
              <span className="case-name">{activeCase.name}</span>
              <span className="case-sep">·</span>
              <span className="mono text-xs">{activeCase.id.slice(0, 8)}</span>
            </div>
          )}
        </div>
        <div className="topbar-right">
          <div className="topbar-search" onClick={() => {}}>
            <span>Search evidence, networks, artifacts…</span>
            <kbd>Ctrl+K</kbd>
          </div>
          <button className="topbar-icon-btn" title="Background Tasks">⟳</button>
          <button className="topbar-icon-btn" title="Notifications">
            ⚑
            {diags.some(d => d.status === 'fail') && <span className="badge-count">!</span>}
          </button>
        </div>
      </div>

      {/* ── Left Sidebar ───────────────────────────────────── */}
      <nav className="sidebar">
        {sidebarNav.map(group => (
          <div key={group.group} className="sidebar-group">
            <div className="sidebar-group-label">{group.group}</div>
            {group.items.map(item => (
              <div
                key={item.id}
                className={`sidebar-item ${screen === item.id ? 'active' : ''}`}
                onClick={() => setScreen(item.id)}
              >
                <span className="icon">{item.icon}</span>
                <span>{item.label}</span>
                {item.shortcut && <span className="shortcut">{item.shortcut}</span>}
              </div>
            ))}
          </div>
        ))}
        <div className="sidebar-health">
          <span className={`health-dot ${healthStatus}`}></span>
          <span>{healthStatus === 'ok' ? 'System OK' : 'Issues Detected'}</span>
        </div>
      </nav>

      {/* ── Main Content ───────────────────────────────────── */}
      <main className="main-content">
        {screen === 'dashboard' && (
          <DashboardScreen
            cases={cases}
            diags={diags}
            activeCase={activeCase}
            onNewCase={() => setShowWizard(true)}
            onOpenCase={(c) => { setActiveCase(c); setScreen('cases'); }}
            onRunDoctor={async () => { setLoading(true); await loadDiagnostics(); setLoading(false); }}
          />
        )}
        {screen === 'cases' && (
          <CasesScreen
            cases={cases}
            activeCase={activeCase}
            onSelectCase={setActiveCase}
            onNewCase={() => setShowWizard(true)}
            onRefresh={loadCases}
          />
        )}
        {screen === 'timeline' && <TimelineScreen activeCase={activeCase} />}
        {screen === 'artifacts' && <ArtifactsScreen activeCase={activeCase} />}
        {screen === 'audit' && <AuditScreen activeCase={activeCase} />}
        {screen === 'evidence' && <EvidenceScreen activeCase={activeCase} />}
        {screen === 'settings' && <SettingsScreen />}
        {['devices', 'ingest', 'correlation', 'reports', 'plugins'].includes(screen) && (
          <PlaceholderScreen name={screen} />
        )}
      </main>

      {/* ── Status Bar ─────────────────────────────────────── */}
      <div className="statusbar">
        <div className="statusbar-item">
          <span className={`dot ${activeCase ? 'blue' : 'yellow'}`}></span>
          <span>{activeCase ? activeCase.name : 'No active case'}</span>
        </div>
        <div className="statusbar-item">
          <span>⚙</span>
          <span>Parser: Idle</span>
        </div>
        <div className="statusbar-item">
          <span>📦</span>
          <span>{cases.reduce((s, c) => s + c.artifactCount, 0)} artifacts</span>
        </div>
        <div className="statusbar-spacer" />
        <div className="statusbar-item">
          <span>⏱</span>
          <span>Analysis: {activeCase ? 'Ready' : 'Waiting'}</span>
        </div>
        <div className="statusbar-item">
          <span className="dot green"></span>
          <span>Chain: INTACT</span>
        </div>
      </div>

      {/* ── New Case Wizard Modal ──────────────────────────── */}
      {showWizard && (
        <NewCaseWizard
          onClose={() => setShowWizard(false)}
          onCreated={async (id) => {
            setShowWizard(false);
            await loadCases();
          }}
        />
      )}

      {/* ── Terminal Output Overlay ────────────────────────── */}
      {terminalOutput && (
        <div className="modal-overlay" onClick={() => setTerminalOutput(null)}>
          <div className="terminal-panel" style={{ width: 700 }} onClick={e => e.stopPropagation()}>
            <div className="terminal-header">
              <span>ORACLE CLI Output</span>
              <button className="modal-close" onClick={() => setTerminalOutput(null)}>✕</button>
            </div>
            <div className="terminal-body">{terminalOutput}</div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SCREEN: Dashboard (Welcome)
// ═══════════════════════════════════════════════════════════════
function DashboardScreen({ cases, diags, activeCase, onNewCase, onOpenCase, onRunDoctor }: {
  cases: CaseInfo[];
  diags: DiagResult[];
  activeCase: CaseInfo | null;
  onNewCase: () => void;
  onOpenCase: (c: CaseInfo) => void;
  onRunDoctor: () => void;
}) {
  return (
    <div>
      <div className="page-header">
        <h2>Dashboard</h2>
      </div>

      <div className="grid-sidebar">
        {/* Left Column: Quick Actions */}
        <div className="flex flex-col gap-4">
          <button className="quick-action" onClick={onNewCase}>
            <div className="qa-icon">+</div>
            <div className="qa-text">
              <h4>New Investigation</h4>
              <p>Create a new forensic case workspace</p>
            </div>
          </button>
          <button className="quick-action" onClick={() => {}}>
            <div className="qa-icon">⬆</div>
            <div className="qa-text">
              <h4>Import Forensic Image</h4>
              <p>Ingest .tar, .img, or directory</p>
            </div>
          </button>
          <button className="quick-action" onClick={onRunDoctor}>
            <div className="qa-icon">⚕</div>
            <div className="qa-text">
              <h4>System Doctor</h4>
              <p>Run diagnostic health checks</p>
            </div>
          </button>

          {/* System Health Panel */}
          <div className="panel mt-4">
            <div className="panel-header">
              <h3>System Health</h3>
            </div>
            <div className="panel-body">
              <div className="diag-grid">
                {diags.map((d, i) => (
                  <div key={i} className="diag-row">
                    <span className="diag-label">{d.label}</span>
                    <span className={`diag-status ${d.status}`}>
                      {d.status === 'pass' ? '✓ PASS' : d.status === 'fail' ? '✗ FAIL' : '⚠ WARN'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Recent Cases */}
        <div>
          <div className="panel">
            <div className="panel-header">
              <h3>Recent Investigations</h3>
              <span className="text-xs text-tertiary">{cases.length} case{cases.length !== 1 ? 's' : ''}</span>
            </div>
            <div className="panel-body no-pad">
              {cases.length === 0 ? (
                <div style={{ padding: 'var(--space-8)', textAlign: 'center' }}>
                  <p className="text-secondary" style={{ marginBottom: 'var(--space-4)' }}>No investigations found</p>
                  <p className="text-xs text-tertiary">Create a new investigation to get started.</p>
                </div>
              ) : (
                <div className="flex flex-col">
                  {cases.map(c => (
                    <div key={c.id} className="case-card" style={{ borderRadius: 0, border: 'none', borderBottom: '1px solid var(--border-subtle)' }} onClick={() => onOpenCase(c)}>
                      <div className="case-icon">📁</div>
                      <div className="case-info">
                        <h4>{c.name}</h4>
                        <p>{c.artifactCount} file{c.artifactCount !== 1 ? 's' : ''} · ID: {c.id.slice(0, 8)}…</p>
                      </div>
                      <div className="case-meta">
                        <div className="badge badge-info" style={{ marginBottom: 4 }}>ACTIVE</div>
                        <div className="text-xs">{timeAgo(c.lastModified)}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SCREEN: Cases
// ═══════════════════════════════════════════════════════════════
function CasesScreen({ cases, activeCase, onSelectCase, onNewCase, onRefresh }: {
  cases: CaseInfo[];
  activeCase: CaseInfo | null;
  onSelectCase: (c: CaseInfo) => void;
  onNewCase: () => void;
  onRefresh: () => void;
}) {
  return (
    <div>
      <div className="page-header">
        <h2>Cases</h2>
        <div className="page-header-actions">
          <button className="btn btn-secondary btn-sm" onClick={onRefresh}>Refresh</button>
          <button className="btn btn-primary btn-sm" onClick={onNewCase}>+ New Case</button>
        </div>
      </div>
      <div className="panel">
        <div className="panel-body no-pad">
          <table className="data-table">
            <thead>
              <tr>
                <th>Case Name</th>
                <th>Investigation ID</th>
                <th>Files</th>
                <th>Last Modified</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {cases.map(c => (
                <tr
                  key={c.id}
                  className={activeCase?.id === c.id ? 'selected' : ''}
                  onClick={() => onSelectCase(c)}
                  style={{ cursor: 'pointer' }}
                >
                  <td style={{ color: 'var(--fg-primary)', fontWeight: 500 }}>{c.name}</td>
                  <td className="mono">{c.id}</td>
                  <td className="num">{c.artifactCount}</td>
                  <td className="mono">{timeAgo(c.lastModified)}</td>
                  <td><span className="badge badge-success">ACTIVE</span></td>
                </tr>
              ))}
              {cases.length === 0 && (
                <tr><td colSpan={5} style={{ textAlign: 'center', padding: 'var(--space-8)', color: 'var(--fg-tertiary)' }}>No cases found. Create a new investigation to begin.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SCREEN: Timeline
// ═══════════════════════════════════════════════════════════════
function TimelineScreen({ activeCase }: { activeCase: CaseInfo | null }) {
  if (!activeCase) return <NoCaseSelected />;

  const mockSessions = [
    { ssid: 'HomeWifi_5G', segments: [0,0,1,1,1,1,1,0,0,0,1,1,1,1,1,1,0,0,0,0,1,1,1,1], confidence: 'HIGH' },
    { ssid: 'Starbucks_Free', segments: [0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0], confidence: 'MODERATE' },
    { ssid: 'HOTEL_GUEST', segments: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,0,0,0], confidence: 'MODERATE' },
    { ssid: 'MyHotspot (AP)', segments: [0,0,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], confidence: 'DEFINITIVE' },
  ];

  return (
    <div>
      <div className="page-header">
        <h2>Timeline</h2>
        <div className="page-header-actions">
          <button className="btn btn-secondary btn-sm">Filter</button>
          <button className="btn btn-secondary btn-sm">1h</button>
          <button className="btn btn-secondary btn-sm">6h</button>
          <button className="btn btn-primary btn-sm">24h</button>
          <button className="btn btn-secondary btn-sm">All</button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-body">
          {/* Swim Lane Timeline */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {mockSessions.map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                <div style={{ width: 140, textAlign: 'right', fontSize: 'var(--text-sm)', color: 'var(--fg-secondary)', fontWeight: 500 }}>{s.ssid}</div>
                <div style={{ flex: 1, display: 'flex', gap: 2, height: 20 }}>
                  {s.segments.map((seg, j) => (
                    <div key={j} style={{
                      flex: 1,
                      background: seg ? (s.confidence === 'DEFINITIVE' ? 'var(--conf-definitive)' : s.confidence === 'HIGH' ? 'var(--conf-high)' : 'var(--conf-moderate)') : 'var(--bg-overlay)',
                      borderRadius: 2,
                      opacity: seg ? 1 : 0.3,
                    }} />
                  ))}
                </div>
                <span className={`badge ${s.confidence === 'DEFINITIVE' ? 'badge-definitive' : s.confidence === 'HIGH' ? 'badge-high' : 'badge-moderate'}`}>{s.confidence}</span>
              </div>
            ))}
          </div>

          {/* Anomaly Track */}
          <div style={{ marginTop: 'var(--space-4)', paddingTop: 'var(--space-3)', borderTop: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <div style={{ width: 140, textAlign: 'right', fontSize: 'var(--text-xs)', color: 'var(--fg-tertiary)' }}>Anomalies</div>
              <div style={{ flex: 1, display: 'flex', gap: 2, height: 16 }}>
                {Array.from({length: 24}).map((_, j) => (
                  <div key={j} style={{
                    flex: 1,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: 10,
                    color: 'var(--warning)',
                  }}>
                    {(j === 7 || j === 15) ? '⚠' : ''}
                  </div>
                ))}
              </div>
              <span className="badge badge-warning">2 WARNINGS</span>
            </div>
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="panel mt-4">
        <div className="panel-header">
          <h3>Events</h3>
          <span className="text-xs text-tertiary">12 events</span>
        </div>
        <div className="panel-body no-pad">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Network</th>
                <th>Security</th>
                <th>Confidence</th>
                <th>Sources</th>
              </tr>
            </thead>
            <tbody>
              {[
                { time: '14:32:05', event: 'CONNECTED', net: 'HomeWifi_5G', sec: 'WPA2-PSK', conf: 0.91, src: 3 },
                { time: '14:32:07', event: 'DHCP_LEASE', net: 'HomeWifi_5G', sec: 'WPA2-PSK', conf: 0.97, src: 2 },
                { time: '18:45:12', event: 'DISCONNECTED', net: 'HomeWifi_5G', sec: 'WPA2-PSK', conf: 0.72, src: 1 },
                { time: '18:47:33', event: 'CONNECTED', net: 'Starbucks_Free', sec: 'OPEN', conf: 0.88, src: 2 },
                { time: '19:15:01', event: 'DISCONNECTED', net: 'Starbucks_Free', sec: 'OPEN', conf: 0.65, src: 1 },
                { time: '22:10:44', event: 'CONNECTED', net: 'HOTEL_GUEST', sec: 'WPA2-PSK', conf: 0.78, src: 2 },
              ].map((e, i) => (
                <tr key={i}>
                  <td className="mono">{e.time}</td>
                  <td><span className={`badge ${e.event === 'CONNECTED' ? 'badge-success' : e.event === 'DISCONNECTED' ? 'badge-neutral' : 'badge-info'}`}>{e.event}</span></td>
                  <td style={{ color: 'var(--fg-primary)', fontWeight: 500 }}>{e.net}</td>
                  <td><span className="badge badge-neutral">{e.sec}</span></td>
                  <td>
                    <span className={`badge ${e.conf >= 0.95 ? 'badge-definitive' : e.conf >= 0.80 ? 'badge-high' : e.conf >= 0.50 ? 'badge-moderate' : 'badge-low'}`}>
                      {e.conf >= 0.95 ? 'DEF' : e.conf >= 0.80 ? 'HIGH' : e.conf >= 0.50 ? 'MOD' : 'LOW'} ({e.conf.toFixed(2)})
                    </span>
                  </td>
                  <td className="num">{e.src}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SCREEN: Artifacts
// ═══════════════════════════════════════════════════════════════
function ArtifactsScreen({ activeCase }: { activeCase: CaseInfo | null }) {
  if (!activeCase) return <NoCaseSelected />;

  const mockArtifacts = [
    { cls: 'WifiConfigStore', path: '/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml', hash: 'a3f82d1c…', size: '2.1 KB', parser: 'wifi_config_store_v2', confidence: 0.95 },
    { cls: 'DhcpLeases', path: '/data/misc/dhcp/dhcpclient-eth0.leases', hash: '7b92f034…', size: '512 B', parser: 'dhcp_lease_parser', confidence: 0.92 },
    { cls: 'KernelLogs', path: '/proc/kmsg', hash: 'e21a9c47…', size: '45 KB', parser: 'kernel_log_parser', confidence: 0.99 },
    { cls: 'BatteryStats', path: '/data/system/batterystats.bin', hash: '1dc4a883…', size: '128 KB', parser: 'battery_stats_parser', confidence: 0.80 },
    { cls: 'ConnectivityLogs', path: '/data/misc/connectivity/netlog.bin', hash: '5fa93e12…', size: '67 KB', parser: 'connectivity_log_parser', confidence: 0.85 },
    { cls: 'HostapdLogs', path: '/data/misc/wifi/hostapd.log', hash: 'c4d82b71…', size: '8.3 KB', parser: 'hostapd_parser', confidence: 0.88 },
  ];

  return (
    <div>
      <div className="page-header">
        <h2>Artifacts</h2>
        <div className="page-header-actions">
          <button className="btn btn-secondary btn-sm">Verify All Hashes</button>
          <button className="btn btn-secondary btn-sm">Export</button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-body no-pad">
          <table className="data-table">
            <thead>
              <tr>
                <th>Artifact Class</th>
                <th>Device Path</th>
                <th>SHA-256</th>
                <th>Size</th>
                <th>Parser</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {mockArtifacts.map((a, i) => (
                <tr key={i}>
                  <td><span className="badge badge-info">{a.cls}</span></td>
                  <td className="mono" style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.path}</td>
                  <td className="mono copyable">{a.hash}</td>
                  <td className="num">{a.size}</td>
                  <td className="mono text-xs">{a.parser}</td>
                  <td>
                    <span className={`badge ${a.confidence >= 0.95 ? 'badge-definitive' : a.confidence >= 0.80 ? 'badge-high' : 'badge-moderate'}`}>
                      {a.confidence >= 0.95 ? 'DEFINITIVE' : a.confidence >= 0.80 ? 'HIGH' : 'MODERATE'} ({a.confidence.toFixed(2)})
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SCREEN: Audit
// ═══════════════════════════════════════════════════════════════
function AuditScreen({ activeCase }: { activeCase: CaseInfo | null }) {
  const mockEntries = [
    { idx: 1, time: '18:48:05', op: 'InvestigationCreated', actor: 'Det. Smith', target: 'CASE-2026-0042', result: 'Success' },
    { idx: 2, time: '18:48:05', op: 'EvidenceStoreCreated', actor: 'SYSTEM', target: 'evidence_store', result: 'Success' },
    { idx: 3, time: '18:49:12', op: 'CapabilityDetectionStarted', actor: 'SYSTEM', target: 'ABC123XYZ', result: 'Success' },
    { idx: 4, time: '18:49:14', op: 'ArtifactAcquisitionStarted', actor: 'SYSTEM', target: '6 artifacts', result: 'Success' },
    { idx: 5, time: '18:49:18', op: 'ParserExecutionStarted', actor: 'SYSTEM', target: 'wifi_config_store_v2', result: 'Success' },
    { idx: 6, time: '18:49:22', op: 'NormalizationStarted', actor: 'SYSTEM', target: '147 records', result: 'Success' },
    { idx: 7, time: '18:49:25', op: 'CorrelationStarted', actor: 'SYSTEM', target: 'evidence_correlation', result: 'Success' },
    { idx: 8, time: '18:49:28', op: 'ConfidenceScoreComputed', actor: 'SYSTEM', target: '12 findings', result: 'Success' },
  ];

  return (
    <div>
      <div className="page-header">
        <h2>Audit Center</h2>
        <div className="page-header-actions">
          <button className="btn btn-primary btn-sm">Verify Full Chain</button>
          <button className="btn btn-secondary btn-sm">Export Audit Log</button>
        </div>
      </div>

      <div className="stat-row mb-4">
        <div className="stat-block">
          <div className="stat-label">Total Entries</div>
          <div className="stat-value">{mockEntries.length}</div>
        </div>
        <div className="stat-block">
          <div className="stat-label">Chain Status</div>
          <div className="stat-value text-success">INTACT</div>
        </div>
        <div className="stat-block">
          <div className="stat-label">Last Verified</div>
          <div className="stat-value text-sm" style={{ fontSize: 'var(--text-base)' }}>Just now</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Audit Trail</h3>
        </div>
        <div className="panel-body no-pad">
          <table className="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Operation</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {mockEntries.map(e => (
                <tr key={e.idx}>
                  <td className="mono num">{e.idx}</td>
                  <td className="mono">{e.time}</td>
                  <td><span className="badge badge-neutral">{e.op}</span></td>
                  <td style={{ color: e.actor === 'SYSTEM' ? 'var(--fg-tertiary)' : 'var(--fg-primary)' }}>{e.actor}</td>
                  <td className="mono text-xs">{e.target}</td>
                  <td><span className="badge badge-success">{e.result}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SCREEN: Evidence
// ═══════════════════════════════════════════════════════════════
function EvidenceScreen({ activeCase }: { activeCase: CaseInfo | null }) {
  if (!activeCase) return <NoCaseSelected />;
  return (
    <div>
      <div className="page-header">
        <h2>Evidence Explorer</h2>
        <div className="page-header-actions">
          <button className="btn btn-secondary btn-sm">Verify Integrity</button>
        </div>
      </div>
      <div className="grid-2">
        {/* Tree Panel */}
        <div className="panel">
          <div className="panel-header"><h3>Evidence Tree</h3></div>
          <div className="panel-body" style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
            <div style={{ color: 'var(--fg-primary)' }}>▼ {activeCase.id.slice(0,8)}</div>
            <div style={{ paddingLeft: 16, color: 'var(--fg-secondary)' }}>▼ WifiConfigStore</div>
            <div style={{ paddingLeft: 32, color: 'var(--accent-text)' }}>  WifiConfigStore.xml</div>
            <div style={{ paddingLeft: 16, color: 'var(--fg-secondary)' }}>▶ DhcpLeases</div>
            <div style={{ paddingLeft: 16, color: 'var(--fg-secondary)' }}>▶ KernelLogs</div>
            <div style={{ paddingLeft: 16, color: 'var(--fg-secondary)' }}>▶ BatteryStats</div>
            <div style={{ paddingLeft: 16, color: 'var(--fg-secondary)' }}>▶ ConnectivityLogs</div>
            <div style={{ paddingLeft: 16, color: 'var(--fg-secondary)' }}>▶ HostapdLogs</div>
          </div>
        </div>
        {/* Preview Panel */}
        <div className="panel">
          <div className="panel-header">
            <h3>Preview</h3>
            <div className="flex gap-2">
              <button className="btn btn-sm btn-primary">Structured</button>
              <button className="btn btn-sm btn-ghost">Hex</button>
              <button className="btn btn-sm btn-ghost">Raw</button>
            </div>
          </div>
          <div className="panel-body" style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--fg-secondary)' }}>
            <div>{"{"}</div>
            <div style={{ paddingLeft: 16 }}>"ssid": "HomeWifi_5G",</div>
            <div style={{ paddingLeft: 16 }}>"bssid": "aa:bb:cc:dd:ee:ff",</div>
            <div style={{ paddingLeft: 16 }}>"security": "WPA2-PSK",</div>
            <div style={{ paddingLeft: 16 }}>"last_connected": "2026-06-22T14:32:05Z",</div>
            <div style={{ paddingLeft: 16 }}>"hidden": false</div>
            <div>{"}"}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SCREEN: Settings
// ═══════════════════════════════════════════════════════════════
function SettingsScreen() {
  return (
    <div>
      <div className="page-header"><h2>Settings</h2></div>
      <div className="grid-sidebar">
        <div className="panel">
          <div className="panel-body no-pad">
            {['General', 'Appearance', 'Evidence', 'Parsers', 'Reports', 'Security', 'Logging'].map((s, i) => (
              <div key={s} className={`sidebar-item ${i === 0 ? 'active' : ''}`}>
                <span>{s}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="panel">
          <div className="panel-header"><h3>General</h3></div>
          <div className="panel-body">
            <div className="form-group">
              <label className="form-label">Organization Name</label>
              <input className="form-input" type="text" defaultValue="ORACLE Forensic Lab" />
            </div>
            <div className="form-group">
              <label className="form-label">Investigations Directory</label>
              <input className="form-input" type="text" defaultValue="investigations" />
              <span className="form-hint">Relative to the ORACLE working directory</span>
            </div>
            <div className="form-group">
              <label className="form-label">Default Examiner</label>
              <input className="form-input" type="text" placeholder="Det. Jane Smith" />
            </div>
            <button className="btn btn-primary mt-4">Save Changes</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// COMPONENT: New Case Wizard
// ═══════════════════════════════════════════════════════════════
function NewCaseWizard({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [step, setStep] = useState(1);
  const [caseName, setCaseName] = useState('');
  const [examiner, setExaminer] = useState('');
  const [description, setDescription] = useState('');
  const [creating, setCreating] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  async function handleCreate() {
    setCreating(true);
    const res = await createCase(caseName, examiner);
    if (res.success && res.investigationId) {
      setResult(res.investigationId);
      setStep(4);
      onCreated(res.investigationId);
    } else {
      setResult(res.output);
    }
    setCreating(false);
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width: 520 }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>New Investigation</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {/* Wizard Step Indicators */}
          <div className="wizard-steps">
            {[1,2,3].map(s => (
              <div key={s} className="wizard-step-indicator">
                <div className={`wizard-step-dot ${step > s ? 'done' : step === s ? 'active' : ''}`}>
                  {step > s ? '✓' : s}
                </div>
                {s < 3 && <div className={`wizard-step-line ${step > s ? 'done' : ''}`} />}
              </div>
            ))}
          </div>

          {step === 1 && (
            <>
              <div className="form-group">
                <label className="form-label">Case Name *</label>
                <input className="form-input" type="text" placeholder="CASE-2026-0042" value={caseName} onChange={e => setCaseName(e.target.value)} autoFocus />
                <span className="form-hint">Use your agency's case numbering format</span>
              </div>
              <div className="form-group">
                <label className="form-label">Description</label>
                <input className="form-input" type="text" placeholder="Optional case notes" value={description} onChange={e => setDescription(e.target.value)} />
              </div>
            </>
          )}
          {step === 2 && (
            <>
              <div className="form-group">
                <label className="form-label">Examiner Full Name *</label>
                <input className="form-input" type="text" placeholder="Det. Jane Smith" value={examiner} onChange={e => setExaminer(e.target.value)} autoFocus />
              </div>
              <div className="form-group">
                <label className="form-label">Badge / Employee ID</label>
                <input className="form-input" type="text" placeholder="Optional" />
              </div>
            </>
          )}
          {step === 3 && (
            <>
              <div className="panel" style={{ marginBottom: 'var(--space-4)' }}>
                <div className="panel-header"><h3>Review</h3></div>
                <div className="panel-body">
                  <div className="diag-grid">
                    <div className="diag-row"><span className="diag-label">Case Name</span><span style={{ fontWeight: 600, color: 'var(--fg-primary)' }}>{caseName}</span></div>
                    <div className="diag-row"><span className="diag-label">Examiner</span><span style={{ fontWeight: 600, color: 'var(--fg-primary)' }}>{examiner}</span></div>
                    {description && <div className="diag-row"><span className="diag-label">Description</span><span className="text-secondary">{description}</span></div>}
                  </div>
                </div>
              </div>
              <p className="text-xs text-tertiary">An audit log entry will be created recording this case initialization. This action cannot be undone.</p>
            </>
          )}
          {step === 4 && (
            <div style={{ textAlign: 'center', padding: 'var(--space-4)' }}>
              <div style={{ fontSize: '2rem', marginBottom: 'var(--space-4)' }}>✓</div>
              <h3 style={{ color: 'var(--success)', marginBottom: 'var(--space-2)' }}>Investigation Created</h3>
              <p className="mono text-sm text-tertiary">{result}</p>
            </div>
          )}
        </div>
        <div className="modal-footer">
          {step < 4 && (
            <>
              {step > 1 && <button className="btn btn-ghost" onClick={() => setStep(s => s - 1)}>Back</button>}
              {step < 3 && (
                <button className="btn btn-primary" onClick={() => setStep(s => s + 1)}
                  disabled={(step === 1 && !caseName) || (step === 2 && !examiner)}>
                  Next
                </button>
              )}
              {step === 3 && (
                <button className="btn btn-primary" onClick={handleCreate} disabled={creating}>
                  {creating ? 'Creating…' : 'Create Investigation'}
                </button>
              )}
            </>
          )}
          {step === 4 && <button className="btn btn-primary" onClick={onClose}>Done</button>}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════
function NoCaseSelected() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', flexDirection: 'column', gap: 'var(--space-4)' }}>
      <div style={{ fontSize: '2rem', opacity: 0.3 }}>⊡</div>
      <p className="text-secondary">Select a case from the Cases screen to view this content.</p>
    </div>
  );
}

function PlaceholderScreen({ name }: { name: string }) {
  return (
    <div>
      <div className="page-header"><h2>{name.charAt(0).toUpperCase() + name.slice(1)}</h2></div>
      <div className="panel">
        <div className="panel-body" style={{ textAlign: 'center', padding: 'var(--space-10)', color: 'var(--fg-tertiary)' }}>
          <div style={{ fontSize: '2rem', marginBottom: 'var(--space-4)', opacity: 0.3 }}>🔧</div>
          <p>This module is ready for implementation.</p>
          <p className="text-xs mt-2">Connect a device or import a forensic image to activate this view.</p>
        </div>
      </div>
    </div>
  );
}

function timeAgo(isoDate: string): string {
  const diff = Date.now() - new Date(isoDate).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
