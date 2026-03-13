"use client"


import React, { useState, useEffect } from 'react';
import { Shield, Smartphone, Network, Brain, Globe, Bell, Search, Download, RefreshCw, MailSearchIcon } from 'lucide-react';
import CybersecurityChatbot from './Chat_Bot';

const API_BASE = 'http://10.4.7.120:8060';
const API_KEY = 'secret-api-key';

const api = async (endpoint, options = {}) => {
  try {
    console.log('🔵 API Request:', {
      endpoint,
      method: options.method || 'GET',
      url: `${API_BASE}${endpoint}`,
    });

    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    console.log('🟢 API Response:', {
      endpoint,
      status: res.status,
      statusText: res.statusText,
    });

    if (!res.ok) throw new Error(`API Error: ${res.status}`);

    const data = await res.json();
    console.log('📦 API Data:', { endpoint, data });

    return data;
  } catch (err) {
    console.error('🔴 API Error:', { endpoint, error: err.message });
    throw err;
  }
};

export default function DASTDashboard() {
  const [view, setView] = useState('dashboard');
  const [summary, setSummary] = useState(null);
  const [scans, setScans] = useState([]);
  const [fixFirst, setFixFirst] = useState([]);
  const [groupedVulns, setGroupedVulns] = useState(null);

  useEffect(() => {
    if (view === 'dashboard') loadDashboard();
    else if (view === 'results') loadResults();
  }, [view]);

  const loadDashboard = async () => {
    console.log('📊 Loading Dashboard...');
    try {
      const [summaryData, scansData, fixData] = await Promise.all([
        api('/api/v1/dashboard/summary'),
        api('/api/v1/dashboard/scans?limit=10'),
        api('/api/v1/dashboard/fix-first?limit=5'),
      ]);
      console.log('✅ Dashboard loaded successfully');
      setSummary(summaryData);
      setScans(scansData);
      setFixFirst(fixData);
    } catch (err) {
      console.error('❌ Dashboard load failed:', err);
    }
  };

  const loadResults = async () => {
    console.log('📊 Loading Results...');
    try {
      const [scansData, groupedData] = await Promise.all([
        api('/api/v1/dashboard/scans?limit=10'),
        api('/api/v1/dashboard/vulnerabilities/grouped'),
      ]);
      console.log('✅ Results loaded successfully');
      setScans(scansData);
      setGroupedVulns(groupedData);
    } catch (err) {
      console.error('❌ Results load failed:', err);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0e1a]">
      <div className="flex">
        <Sidebar view={view} setView={setView} />

        <div className="flex-1">
          <Header />

          <main className="p-8">
            {view === 'dashboard' && <Dashboard summary={summary} scans={scans} fixFirst={fixFirst} />}
            {view === 'web' && <WebScan />}
            {view === 'app' && <AppScan />}
            {view === 'network' && <NetworkScan />}
            {view === 'ai' && <AIScan />}
            {view === 'results' && <Results scans={scans} groupedVulns={groupedVulns} />}
            {view === 'chat' && <CybersecurityChatbot />}
          </main>
        </div>
      </div>
    </div>
  );
}

function Sidebar({ view, setView }) {
  const items = [
    { id: 'dashboard', icon: <Shield size={20} />, label: 'Dashboard' },
    { id: 'web', icon: <Globe size={20} />, label: 'Website Scan' },
    { id: 'app', icon: <Smartphone size={20} />, label: 'App Scan' },
    { id: 'network', icon: <Network size={20} />, label: 'Network Scan' },
    { id: 'ai', icon: <Brain size={20} />, label: 'AI Risk Scan' },
    { id: 'results', icon: <Shield size={20} />, label: 'Results' },
    { id: 'chat', icon: <MailSearchIcon size={20} />, label: 'Chats' },
  ];

  return (
    <div className="w-64 bg-[#0f1420] border-r border-gray-800 min-h-screen">
      <div className="p-6">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 bg-red-600 rounded-lg flex items-center justify-center">
            <Shield className="text-white" size={24} />
          </div>
          <div>
            <span className="text-white text-xl font-bold">Sentinel</span>
            <span className="text-red-500 text-xl font-bold">Shield</span>
          </div>
        </div>

        <nav className="space-y-1">
          {items.map((item) => (
            <button
              key={item.id}
              onClick={() => setView(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition ${view === item.id
                ? 'bg-red-600/20 text-red-500 border border-red-600/30'
                : 'text-gray-400 hover:bg-gray-800/50'
                }`}
            >
              {item.icon}
              <span className="text-sm font-medium">{item.label}</span>
            </button>
          ))}
        </nav>
      </div>
    </div>
  );
}

function Header() {
  return (
    <div className="bg-[#0f1420] border-b border-gray-800 px-8 py-4">
      <div className="flex items-center justify-between">
        <div className="flex-1 max-w-xl">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={20} />
            <input
              type="text"
              placeholder="Search targets, scans, or vulnerabilities..."
              className="w-full bg-[#1a1f2e] border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-600"
            />
          </div>
        </div>
        <button className="ml-4 p-2 hover:bg-gray-800 rounded-lg">
          <Bell className="text-gray-400" size={20} />
        </button>
      </div>
    </div>
  );
}

function Dashboard({ summary, scans, fixFirst }) {
  if (!summary) return <div className="text-gray-400">Loading...</div>;

  const stats = [
    { label: 'Total Vulnerabilities', value: summary.total_vulnerabilities },
    { label: 'Critical', value: summary.count_by_severity.critical || 0 },
    { label: 'High', value: summary.count_by_severity.high || 0 },
    { label: 'Medium', value: summary.count_by_severity.medium || 0 },
  ];

  const assets = [
    { label: 'Web', value: summary.count_by_asset_type.Web || 0, icon: <Globe size={24} /> },
    { label: 'Mobile', value: summary.count_by_asset_type.Mobile || 0, icon: <Smartphone size={24} /> },
    { label: 'Network', value: summary.count_by_asset_type.Network || 0, icon: <Network size={24} /> },
    { label: 'LLM', value: summary.count_by_asset_type.LLM || 0, icon: <Brain size={24} /> },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-4 gap-4">
        {stats.map((stat, i) => (
          <div key={i} className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">{stat.label}</div>
            <div className="text-3xl font-bold text-white">{stat.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-4 gap-4">
        {assets.map((asset, i) => (
          <div key={i} className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="text-gray-400">{asset.icon}</div>
              <div>
                <div className="text-sm text-gray-400">{asset.label}</div>
                <div className="text-2xl font-bold text-white">{asset.value}</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {fixFirst && fixFirst.length > 0 && (
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-bold text-white mb-4">Fix First - Top Priority</h2>
          <div className="space-y-2">
            {fixFirst.map((vuln) => (
              <div key={vuln.id} className="flex items-center justify-between p-3 bg-[#0f1420] rounded-lg">
                <div className="flex-1">
                  <div className="font-medium text-white">{vuln.name}</div>
                  <div className="text-sm text-gray-400">{vuln.asset || vuln.url}</div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-400">Risk: {vuln.risk_score?.toFixed(1) || 0}</span>
                  <SeverityBadge severity={vuln.severity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {scans && scans.length > 0 && (
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-bold text-white mb-4">Recent Scans</h2>
          <div className="space-y-2">
            {scans.map((scan) => (
              <div key={scan.scan_id} className="flex items-center justify-between p-3 bg-[#0f1420] rounded-lg">
                <div className="flex-1">
                  <div className="font-medium text-white">{scan.target}</div>
                  <div className="text-sm text-gray-400">
                    C:{scan.summary?.critical || 0} H:{scan.summary?.high || 0} M:{scan.summary?.medium || 0} L:{scan.summary?.low || 0}
                  </div>
                </div>
                <StatusBadge status={scan.status} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function WebScan() {
  const [target, setTarget] = useState('');
  const [scanId, setScanId] = useState('');
  const [status, setStatus] = useState(null);
  const [result, setResult] = useState(null);
  const [logs, setLogs] = useState([]);

  const startScan = async () => {
    console.log('🚀 Starting web scan...', { target });
    try {
      const res = await api('/api/v1/acunetix/scan', {
        method: 'POST',
        body: JSON.stringify({ target }),
      });
      console.log('✅ Scan started:', res.scan_id);
      setScanId(res.scan_id);
      setStatus(null);
      setResult(null);
    } catch (err) {
      console.error('❌ Scan failed:', err);
      alert(`Error: ${err.message}`);
    }
  };

  const checkStatus = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/acunetix/status/${scanId}`);
      setStatus(res);
    } catch (err) {
      console.error(err);
    }
  };

  const getResults = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/acunetix/results/${scanId}`);
      setResult(res);
    } catch (err) {
      console.error(err);
    }
  };

  const getLogs = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/logs/${scanId}`);
      setLogs(res);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
        <h2 className="text-xl font-bold text-white mb-6">Website Scan</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Target URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full bg-[#0f1420] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-gray-600"
            />
          </div>
          <button
            onClick={startScan}
            className="w-full bg-red-600 hover:bg-red-700 text-white font-medium py-3 rounded-lg transition"
          >
            Start Scan
          </button>
        </div>
      </div>

      {scanId && (
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-bold text-white mb-4">Scan ID: {scanId}</h3>
          <div className="flex gap-2 mb-4">
            <button onClick={checkStatus} className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg flex items-center gap-2">
              <RefreshCw size={16} /> Check Status
            </button>
            <button onClick={getResults} className="bg-green-700 hover:bg-green-600 text-white px-4 py-2 rounded-lg">
              Get Results
            </button>
            <button onClick={getLogs} className="bg-blue-700 hover:bg-blue-600 text-white px-4 py-2 rounded-lg">
              View Logs
            </button>
          </div>

          {status && (
            <div className="mb-4 p-4 bg-[#0f1420] rounded-lg">
              <div className="text-sm text-gray-400">Status</div>
              <div className="flex items-center gap-2 mt-1">
                <StatusBadge status={status.status} />
                {status.progress !== undefined && (
                  <span className="text-gray-300">Progress: {status.progress}%</span>
                )}
              </div>
              {status.message && <div className="text-sm text-gray-400 mt-2">{status.message}</div>}
            </div>
          )}

          {result && (
            <div className="mb-4">
              <h4 className="text-white font-medium mb-2">Vulnerabilities Found: {result.vulnerabilities?.length || 0}</h4>
              <div className="space-y-2 max-h-96 overflow-auto">
                {result.vulnerabilities?.map((vuln) => (
                  <VulnerabilityCard key={vuln.id} vuln={vuln} />
                ))}
              </div>
            </div>
          )}

          {logs.length > 0 && (
            <div>
              <h4 className="text-white font-medium mb-2">Logs</h4>
              <pre className="bg-[#0f1420] p-4 rounded text-sm text-gray-300 overflow-auto max-h-64">
                {logs.join('\n')}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AppScan() {
  const [file, setFile] = useState(null);
  const [scanId, setScanId] = useState('');
  const [status, setStatus] = useState(null);
  const [findings, setFindings] = useState([]);

  const startScan = async () => {
    if (!file) return;
    console.log('📤 Uploading app...', file.name);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch(`${API_BASE}/api/v1/mobsf/scan`, {
        method: 'POST',
        headers: { 'X-API-Key': API_KEY },
        body: formData,
      });
      const data = await res.json();
      console.log('✅ Scan started:', data.scan_id);
      setScanId(data.scan_id);
    } catch (err) {
      console.error('❌ Scan failed:', err);
      alert(`Error: ${err.message}`);
    }
  };

  const checkStatus = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/mobsf/status/${scanId}`);
      setStatus(res);
    } catch (err) {
      console.error(err);
    }
  };

  const getFindings = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/mobsf/findings/${scanId}`);
      setFindings(res);
    } catch (err) {
      console.error(err);
    }
  };

  const downloadReport = async () => {
    if (!scanId) return;
    try {
      const res = await fetch(`${API_BASE}/api/v1/mobsf/report/${scanId}`, {
        headers: { 'X-API-Key': API_KEY },
      });
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `mobsf-report-${scanId}.pdf`;
      a.click();
    } catch (err) {
      console.error(err);
      alert(`Error downloading report: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
        <h2 className="text-xl font-bold text-white mb-6">Mobile App Scan</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Upload APK/IPA/ZIP</label>
            <input
              type="file"
              accept=".apk,.ipa,.zip"
              onChange={(e) => setFile(e.target.files[0])}
              className="w-full bg-[#0f1420] border border-gray-700 rounded-lg px-4 py-3 text-gray-300"
            />
          </div>
          <button
            onClick={startScan}
            disabled={!file}
            className="w-full bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white font-medium py-3 rounded-lg transition"
          >
            Start Scan
          </button>
        </div>
      </div>

      {scanId && (
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-bold text-white mb-4">Scan ID: {scanId}</h3>
          <div className="flex gap-2 mb-4">
            <button onClick={checkStatus} className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg">
              Check Status
            </button>
            <button onClick={getFindings} className="bg-green-700 hover:bg-green-600 text-white px-4 py-2 rounded-lg">
              Get Findings
            </button>
            <button onClick={downloadReport} className="bg-blue-700 hover:bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center gap-2">
              <Download size={16} /> Download Report
            </button>
          </div>

          {status && (
            <div className="mb-4 p-4 bg-[#0f1420] rounded-lg">
              <StatusBadge status={status.status} />
            </div>
          )}

          {findings.length > 0 && (
            <div className="space-y-2 max-h-96 overflow-auto">
              {findings.map((finding) => (
                <VulnerabilityCard key={finding.id} vuln={finding} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function NetworkScan() {
  const [target, setTarget] = useState('');
  const [scanId, setScanId] = useState('');
  const [status, setStatus] = useState(null);
  const [results, setResults] = useState([]);

  const startScan = async () => {
    try {
      const res = await api('/api/v1/nmap/scan', {
        method: 'POST',
        body: JSON.stringify({ target }),
      });
      setScanId(res.scan_id);
    } catch (err) {
      console.error(err);
      alert(`Error: ${err.message}`);
    }
  };

  const checkStatus = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/nmap/status/${scanId}`);
      setStatus(res);
    } catch (err) {
      console.error(err);
    }
  };

  const getResults = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/nmap/results/${scanId}`);
      setResults(res);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
        <h2 className="text-xl font-bold text-white mb-6">Network Scan</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Target IP/Domain</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.1.1 or example.com"
              className="w-full bg-[#0f1420] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-gray-600"
            />
          </div>
          <button
            onClick={startScan}
            className="w-full bg-red-600 hover:bg-red-700 text-white font-medium py-3 rounded-lg transition"
          >
            Start Scan
          </button>
        </div>
      </div>

      {scanId && (
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-bold text-white mb-4">Scan ID: {scanId}</h3>
          <div className="flex gap-2 mb-4">
            <button onClick={checkStatus} className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg">
              Check Status
            </button>
            <button onClick={getResults} className="bg-green-700 hover:bg-green-600 text-white px-4 py-2 rounded-lg">
              Get Results
            </button>
          </div>

          {status && (
            <div className="mb-4 p-4 bg-[#0f1420] rounded-lg">
              <StatusBadge status={status.status} />
            </div>
          )}

          {results.length > 0 && (
            <div className="space-y-2 max-h-96 overflow-auto">
              {results.map((finding) => (
                <VulnerabilityCard key={finding.id} vuln={finding} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AIScan() {
  const [target, setTarget] = useState('');
  const [probes, setProbes] = useState('');
  const [generations, setGenerations] = useState('10');
  const [scanId, setScanId] = useState('');
  const [availableProbes, setAvailableProbes] = useState([]);
  const [availableModels, setAvailableModels] = useState([]);
  const [status, setStatus] = useState(null);
  const [results, setResults] = useState([]);

  useEffect(() => {
    loadProbes();
    loadModels();
  }, []);

  const loadProbes = async () => {
    try {
      const data = await api('/api/v1/garak/probes');
      setAvailableProbes(data);
    } catch (err) {
      console.error(err);
    }
  };

  const loadModels = async () => {
    try {
      const data = await api('/api/v1/garak/models?limit=50');
      setAvailableModels(data);
    } catch (err) {
      console.error(err);
    }
  };

  const startScan = async () => {
    try {
      const res = await api('/api/v1/garak/scan', {
        method: 'POST',
        body: JSON.stringify({
          target,
          probes: probes || null,
          generations: parseInt(generations) || null,
        }),
      });
      setScanId(res.scan_id);
    } catch (err) {
      console.error(err);
      alert(`Error: ${err.message}`);
    }
  };

  const checkStatus = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/garak/status/${scanId}`);
      setStatus(res);
    } catch (err) {
      console.error(err);
    }
  };

  const getResults = async () => {
    if (!scanId) return;
    try {
      const res = await api(`/api/v1/garak/results/${scanId}`);
      setResults(res);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <Brain className="text-purple-500" size={28} />
            <h2 className="text-2xl font-bold text-white">AI Model Risk Assessment</h2>
          </div>
          <p className="text-gray-400">Scan LLM models for vulnerabilities using Garak probes</p>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Target LLM Model ({availableModels.length} available)</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., gpt-4, claude-3-opus, or custom-model:8000"
              className="w-full bg-[#252b3b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-gray-600"
              list="models-list"
            />
            <datalist id="models-list">
              {availableModels.map((model, i) => (
                <option key={i} value={model} />
              ))}
            </datalist>
            <p className="text-xs text-gray-500 mt-1">Select from popular models or enter a custom endpoint</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Vulnerability Probes ({availableProbes.length} available)
            </label>
            <select
              value={probes}
              onChange={(e) => setProbes(e.target.value)}
              className="w-full bg-[#252b3b] border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-gray-600"
            >
              <option value="">Select probes...</option>
              {availableProbes.map((probe, i) => (
                <option key={i} value={probe}>{probe}</option>
              ))}
            </select>
            <p className="text-xs text-gray-500 mt-1">Select attack vectors to test against the LLM</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Generations per Probe</label>
            <input
              type="number"
              value={generations}

              onChange={(e) => setGenerations(e.target.value)}
              min="1"
              max="1000"
              className="w-full bg-[#252b3b] border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-gray-600"
            />
            <p className="text-xs text-gray-500 mt-1">Number of test cases to generate per probe (1-1000)</p>
          </div>

          <button
            onClick={startScan}
            className="w-full bg-purple-600 hover:bg-purple-700 text-white font-medium py-3 rounded-lg transition flex items-center justify-center gap-2"
          >
            <span>▶</span>
            Start LLM Scan
          </button>
        </div>
      </div>

      {scanId && (
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-bold text-white mb-4">Scan ID: {scanId}</h3>
          <div className="flex gap-2 mb-4">
            <button onClick={checkStatus} className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg">
              Check Status
            </button>
            <button onClick={getResults} className="bg-green-700 hover:bg-green-600 text-white px-4 py-2 rounded-lg">
              Get Results
            </button>
          </div>

          {status && (
            <div className="mb-4 p-4 bg-[#0f1420] rounded-lg">
              <StatusBadge status={status.status} />
            </div>
          )}

          {results.length > 0 && (
            <div className="space-y-2 max-h-96 overflow-auto">
              {results.map((finding) => (
                <VulnerabilityCard key={finding.id} vuln={finding} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Results({ scans, groupedVulns }) {
  const [activeTab, setActiveTab] = useState('web');

  const tabs = [
    { id: 'web', label: 'Website Scan', icon: <Globe size={18} /> },
    { id: 'mobile', label: 'App Scan', icon: <Smartphone size={18} /> },
    { id: 'network', label: 'Network Scan', icon: <Network size={18} /> },
    { id: 'llm', label: 'AI Risk Scan', icon: <Brain size={18} /> },
  ];

  const getCurrentData = () => {
    if (!groupedVulns) return [];
    const tabMap = {
      web: groupedVulns.Web || [],
      mobile: groupedVulns.Mobile || [],
      network: groupedVulns.Network || [],
      llm: groupedVulns.LLM || [],
    };
    return tabMap[activeTab] || [];
  };

  const currentData = getCurrentData();

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white">Scan Results</h1>

      <div className="flex gap-2 border-b border-gray-800">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-6 py-3 font-medium transition ${activeTab === tab.id
              ? 'text-red-500 border-b-2 border-red-500'
              : 'text-gray-400 hover:text-gray-300'
              }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-8">
        {!groupedVulns ? (
          <div className="flex flex-col items-center justify-center py-12">
            <div className="text-gray-400">Loading results...</div>
          </div>
        ) : currentData.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12">
            <Globe className="text-gray-600 mb-4" size={64} />
            <p className="text-gray-400">No results yet. Run a scan to see results here.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {currentData.map((vuln) => (
              <div key={vuln.id} className="bg-[#0f1420] border border-gray-700 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <div className="font-medium text-white text-lg">{vuln.name}</div>
                    <div className="text-sm text-gray-400">{vuln.asset || vuln.url}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={vuln.severity} />
                  </div>
                </div>
                {vuln.description && (
                  <p className="text-sm text-gray-300 mb-2">{vuln.description}</p>
                )}
                <div className="flex items-center gap-4 text-xs text-gray-500">
                  <span>Scanner: {vuln.scanner}</span>
                  {vuln.cwe && <span>CWE: {vuln.cwe}</span>}
                  {vuln.cvss && <span>CVSS: {vuln.cvss}</span>}
                  <span>Risk: {vuln.risk_score?.toFixed(1) || 0}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {scans && scans.length > 0 && (
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-bold text-white mb-4">Recent Scans</h2>
          <div className="space-y-2">
            {scans.map((scan) => (
              <div key={scan.scan_id} className="flex items-center justify-between p-3 bg-[#0f1420] rounded-lg">
                <div className="flex-1">
                  <div className="font-medium text-white">{scan.target}</div>
                  <div className="text-sm text-gray-400">
                    {new Date(scan.timestamp).toLocaleString()} • {scan.scan_type || 'N/A'}
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-sm text-gray-400">
                    C:{scan.summary?.critical || 0} H:{scan.summary?.high || 0} M:{scan.summary?.medium || 0}
                  </div>
                  <StatusBadge status={scan.status} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function VulnerabilityCard({ vuln }) {
  return (
    <div className="bg-[#0f1420] border border-gray-700 rounded-lg p-4">
      <div className="flex items-start justify-between mb-2">
        <div className="flex-1">
          <div className="font-medium text-white text-lg">{vuln.name || vuln.title}</div>
          <div className="text-sm text-gray-400">{vuln.asset || vuln.url || vuln.target}</div>
        </div>
        <SeverityBadge severity={vuln.severity} />
      </div>
      {vuln.description && (
        <p className="text-sm text-gray-300 mb-2">{vuln.description}</p>
      )}
      <div className="flex items-center gap-4 text-xs text-gray-500">
        <span>Scanner: {vuln.scanner || 'N/A'}</span>
        {vuln.cwe && <span>CWE: {vuln.cwe}</span>}
        {vuln.cvss && <span>CVSS: {vuln.cvss}</span>}
        {vuln.risk_score !== undefined && <span>Risk: {vuln.risk_score.toFixed(1)}</span>}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const colors = {
    critical: 'bg-purple-900/50 text-purple-300 border border-purple-700',
    high: 'bg-red-900/50 text-red-300 border border-red-700',
    medium: 'bg-orange-900/50 text-orange-300 border border-orange-700',
    low: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
    info: 'bg-blue-900/50 text-blue-300 border border-blue-700',
  };
  return (
    <span className={`px-3 py-1 rounded text-xs font-medium ${colors[severity] || 'bg-gray-800 text-gray-400'}`}>
      {severity?.toUpperCase()}
    </span>
  );
}

function StatusBadge({ status }) {
  const colors = {
    completed: 'bg-green-900/50 text-green-300 border border-green-700',
    running: 'bg-blue-900/50 text-blue-300 border border-blue-700',
    failed: 'bg-red-900/50 text-red-300 border border-red-700',
    pending: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
    queued: 'bg-gray-900/50 text-gray-300 border border-gray-700',
  };
  return (
    <span className={`px-3 py-1 rounded text-xs font-medium ${colors[status] || 'bg-gray-800 text-gray-400'}`}>
      {status?.toUpperCase()}
    </span>
  );
}

