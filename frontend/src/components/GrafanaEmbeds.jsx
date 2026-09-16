import React from 'react';
import { LineChart, Activity, Clock, Shield } from 'lucide-react';

export default function GrafanaEmbeds() {
  const trendDays = [
    { day: 'D-6', val: 45, label: '₹45L' },
    { day: 'D-5', val: 62, label: '₹62L' },
    { day: 'D-4', val: 78, label: '₹78L' },
    { day: 'D-3', val: 95, label: '₹95L' },
    { day: 'D-2', val: 84, label: '₹84L' },
    { day: 'D-1', val: 70, label: '₹70L' },
    { day: 'Today', val: 58, label: '₹58L' },
  ];

  const mttrData = [
    { tool: 'Semgrep (SAST)', hours: '4.2 hrs', pct: 40, col: 'bg-indigo-500' },
    { tool: 'Checkov (IaC)', hours: '2.8 hrs', pct: 28, col: 'bg-blue-500' },
    { tool: 'Cosign (Supply)', hours: '1.5 hrs', pct: 15, col: 'bg-cyan-500' },
    { tool: 'Falco (Runtime)', hours: '0.8 hrs', pct: 8, col: 'bg-amber-500' },
    { tool: 'Suricata (Network)', hours: '2.1 hrs', pct: 21, col: 'bg-purple-500' },
    { tool: 'ZAP (DAST)', hours: '6.4 hrs', pct: 64, col: 'bg-red-500' }
  ];

  return (
    <div className="space-y-6">
      <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <LineChart className="w-4 h-4 text-blue-400" />
              <span>Live Grafana Telemetry & Risk Quantification Trends</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Embedded dashboard telemetry tracking risk exposure trends and remediation velocity
            </p>
          </div>
          <span className="text-xs font-mono text-emerald-400 flex items-center space-x-1.5 bg-emerald-500/10 px-3 py-1 rounded-full border border-emerald-500/20">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Live Syncing from Prometheus</span>
          </span>
        </div>

        {/* Visual Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Panel 1: Exposure Trend Chart */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between h-72">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-slate-200">7-Day Financial Risk Exposure (₹ Lakhs)</span>
              <span className="text-xs text-slate-500 font-mono">Grafana Panel #101</span>
            </div>

            {/* Simulated Bar Chart */}
            <div className="flex items-end space-x-3 h-44 pt-4 px-2">
              {trendDays.map((item, i) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group">
                  <span className="text-[10px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity">
                    {item.label}
                  </span>
                  <div
                    className="w-full bg-gradient-to-t from-blue-600 via-indigo-500 to-cyan-400 rounded-t-lg transition-all duration-300 hover:brightness-125"
                    style={{ height: `${item.val}%` }}
                  ></div>
                  <span className="text-[10px] font-semibold text-slate-500">{item.day}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Panel 2: Mean Time to Remediate (MTTR) */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between h-72">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-slate-200">Mean Time to Remediate (MTTR by Tool)</span>
              <span className="text-xs text-slate-500 font-mono">Grafana Panel #102</span>
            </div>

            <div className="space-y-3 pt-2">
              {mttrData.map((item, idx) => (
                <div key={idx} className="text-xs">
                  <div className="flex justify-between mb-1">
                    <span className="text-slate-300 font-medium">{item.tool}</span>
                    <span className="font-mono text-slate-400 font-semibold">{item.hours}</span>
                  </div>
                  <div className="w-full bg-slate-800/80 rounded-full h-2 overflow-hidden">
                    <div className={`${item.col} h-2 rounded-full`} style={{ width: `${item.pct}%` }}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
