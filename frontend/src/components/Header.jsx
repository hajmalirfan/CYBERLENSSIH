import React, { useState, useEffect } from 'react';
import { Download, Database, Radio, PlusCircle, LogOut, Cpu, CheckCircle2, AlertCircle } from 'lucide-react';
import { fetchOllamaStatus } from '../services/api';

export default function Header({ role, user, onLogout, onOpenScan, onOpenEvidence }) {
  const [ollamaStatus, setOllamaStatus] = useState({ connected: false, ollama_url: 'http://localhost:11434', configured_model: 'mistral' });
  const [showOllamaModal, setShowOllamaModal] = useState(false);

  useEffect(() => {
    async function checkOllama() {
      const stat = await fetchOllamaStatus();
      if (stat) setOllamaStatus(stat);
    }
    checkOllama();
    const interval = setInterval(checkOllama, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 border-b border-slate-200 bg-white/90 backdrop-blur-md px-6 flex items-center justify-between shrink-0">
      {/* Platform Connectivity Status Badges */}
      <div className="flex items-center space-x-3">
        <span className="flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200 font-medium">
          <Database className="w-3.5 h-3.5" />
          <span>Apache AGE Knowledge Graph</span>
        </span>

        <span className="hidden sm:flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded-full bg-slate-100 text-slate-500 border border-slate-200 font-mono">
          <Radio className="w-3 h-3 text-emerald-500 animate-pulse" />
          <span>Kafka: findings.raw</span>
        </span>

        {/* Ollama Connection Pill */}
        <button
          onClick={() => setShowOllamaModal(true)}
          className={`flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded-full border transition-all ${
            ollamaStatus.connected
              ? 'bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100'
              : 'bg-amber-50 text-amber-700 border-amber-300 hover:bg-amber-100'
          }`}
          title="Click to view Ollama details and remote laptop connection info"
        >
          <Cpu className="w-3.5 h-3.5" />
          <span className="font-semibold">Ollama:</span>
          <span>{ollamaStatus.connected ? 'Connected' : 'localhost:11434'}</span>
          <span className={`w-2 h-2 rounded-full ${ollamaStatus.connected ? 'bg-emerald-500 animate-ping' : 'bg-amber-400'}`}></span>
        </button>
      </div>

      {/* Ollama Info Modal */}
      {showOllamaModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-slate-200 space-y-4">
            <div className="flex items-center justify-between border-b pb-3">
              <div className="flex items-center space-x-2">
                <Cpu className="w-5 h-5 text-indigo-600" />
                <h3 className="font-bold text-slate-900">Ollama AI Connection</h3>
              </div>
              <button onClick={() => setShowOllamaModal(false)} className="text-slate-400 hover:text-slate-600 text-sm font-bold">✕</button>
            </div>
            
            <div className="space-y-3 text-xs text-slate-600">
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border">
                <span className="font-medium text-slate-500">Status:</span>
                <span className={`font-bold flex items-center space-x-1 ${ollamaStatus.connected ? 'text-emerald-600' : 'text-amber-600'}`}>
                  {ollamaStatus.connected ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                  <span>{ollamaStatus.connected ? 'Online & Active' : 'Offline / Standby'}</span>
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border">
                <span className="font-medium text-slate-500">Endpoint:</span>
                <span className="font-mono text-slate-800 font-semibold">{ollamaStatus.ollama_url || 'http://localhost:11434'}</span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border">
                <span className="font-medium text-slate-500">Configured Model:</span>
                <span className="font-mono text-indigo-600 font-bold">{ollamaStatus.configured_model || 'mistral'}</span>
              </div>

              {ollamaStatus.available_models && ollamaStatus.available_models.length > 0 && (
                <div className="p-3 rounded-xl bg-slate-50 border">
                  <div className="font-medium text-slate-500 mb-1">Installed Models:</div>
                  <div className="flex flex-wrap gap-1">
                    {ollamaStatus.available_models.map((m) => (
                      <span key={m} className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 text-[10px] font-mono font-bold">
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="p-3 rounded-xl bg-blue-50 border border-blue-200 text-blue-900 text-[11px] leading-relaxed">
                <strong>Connecting from another laptop:</strong>
                <p className="mt-1">1. Run Ollama on the other laptop with <code className="bg-blue-100 px-1 rounded">OLLAMA_HOST=0.0.0.0 ollama serve</code></p>
                <p>2. Set <code className="bg-blue-100 px-1 rounded">OLLAMA_BASE_URL=http://&lt;laptop-ip&gt;:11434</code> in <code className="bg-blue-100 px-1 rounded">.env</code></p>
                <p className="mt-1 text-slate-500">SecuriX automatically detects Ollama and switches between live inference and expert cyber heuristics without restarts.</p>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowOllamaModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-900 text-white text-xs font-bold hover:bg-slate-800"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Logged-in user + Primary Action Buttons (no static role switcher) */}
      <div className="flex items-center space-x-3">
        {user && (
          <div className="hidden md:flex items-center space-x-2 text-xs px-2.5 py-1 rounded-full bg-slate-100 text-slate-600 border border-slate-200 font-medium">
            <span className="font-semibold text-slate-800">{user.name}</span>
            <span className="text-slate-400">·</span>
            <span className="capitalize text-blue-600">{role}</span>
          </div>
        )}

        {/* Trigger Investigation */}
        {role !== 'cfo' && (
          <button
            onClick={onOpenScan}
            className="flex items-center space-x-2 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-bold shadow-md shadow-blue-500/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>+ Add Source / Scan</span>
          </button>
        )}

        {/* Download Evidence Report */}
        <button
          onClick={onOpenEvidence}
          className="flex items-center space-x-2 px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-700 text-xs font-semibold shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Evidence Pack</span>
        </button>

        {/* Logout (DB session) */}
        <button
          onClick={onLogout}
          title="Logout"
          className="flex items-center space-x-2 px-3.5 py-1.5 rounded-xl bg-red-50 hover:bg-red-100 border border-red-200 text-red-600 text-xs font-semibold transition-all"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span>Logout</span>
        </button>
      </div>
    </header>
  );
}
