import React from 'react';
import { Play, Download, Database, Radio, PlusCircle } from 'lucide-react';

export default function Header({ role, setRole, onOpenScan, onOpenEvidence }) {
  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#0c1220]/80 backdrop-blur-md px-6 flex items-center justify-between shrink-0">
      {/* Platform Connectivity Status Badges */}
      <div className="flex items-center space-x-3">
        <span className="flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-medium">
          <Database className="w-3.5 h-3.5" />
          <span>Apache AGE Knowledge Graph</span>
        </span>
        <span className="hidden sm:flex items-center space-x-1.5 text-xs px-2.5 py-1 rounded-full bg-slate-800/80 text-slate-400 border border-slate-700/80 font-mono">
          <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
          <span>Kafka: findings.raw</span>
        </span>
      </div>

      {/* Role Switcher & Primary Action Buttons */}
      <div className="flex items-center space-x-3">
        {/* Role Switcher */}
        <div className="flex bg-slate-900 border border-slate-800 rounded-xl p-1 text-xs font-semibold">
          <button
            onClick={() => setRole('analyst')}
            className={`px-3 py-1 rounded-lg transition-all ${
              role === 'analyst' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Analyst
          </button>
          <button
            onClick={() => setRole('cfo')}
            className={`px-3 py-1 rounded-lg transition-all ${
              role === 'cfo' ? 'bg-emerald-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            CFO (₹)
          </button>
          <button
            onClick={() => setRole('auditor')}
            className={`px-3 py-1 rounded-lg transition-all ${
              role === 'auditor' ? 'bg-amber-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Auditor
          </button>
        </div>

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
          className="flex items-center space-x-2 px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Evidence Pack</span>
        </button>
      </div>
    </header>
  );
}
