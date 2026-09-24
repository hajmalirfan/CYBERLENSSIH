import React from 'react';
import { Download, Database, Radio, PlusCircle, LogOut } from 'lucide-react';

export default function Header({ role, user, onLogout, onOpenScan, onOpenEvidence }) {
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
      </div>

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
