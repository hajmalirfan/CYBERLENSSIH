import React from 'react';
import { Scale, CheckCircle2, XCircle, ShieldCheck, FileSpreadsheet } from 'lucide-react';
import { COMPLIANCE_REGULATIONS, OPA_VERDICTS } from '../data/mockData';

export default function CompliancePlugin() {
  return (
    <div className="space-y-6">
      {/* Overview Cards by Regulation */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {COMPLIANCE_REGULATIONS.map((c) => (
          <div key={c.reg} className="glass-card glass-card-hover rounded-2xl p-4 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-black text-blue-400 font-mono tracking-wider">{c.reg}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${c.score >= 85 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'}`}>
                  {c.score}%
                </span>
              </div>
              <div className="text-xs font-semibold text-slate-200 mt-2 line-clamp-1" title={c.name}>
                {c.name}
              </div>
              <div className="text-[10px] text-slate-500 truncate mt-0.5">{c.authority}</div>
            </div>

            <div className="flex items-center justify-between text-[11px] mt-4 pt-3 border-t border-slate-800/80 font-mono">
              <span className="text-emerald-400 font-bold flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3" />
                <span>{c.pass} Pass</span>
              </span>
              <span className="text-red-400 font-bold flex items-center space-x-1">
                <XCircle className="w-3 h-3" />
                <span>{c.fail} Fail</span>
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* OPA Rego Policy Enforcement Verdicts */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <Scale className="w-4 h-4 text-blue-400" />
              <span>Open Policy Agent (OPA) Rego Enforcement Engine</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Automated compliance evaluations running OPA policies against Apache AGE findings
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400 bg-slate-800 px-3 py-1 rounded-lg">
            OPA Evaluated: 6 Controls Failed
          </span>
        </div>

        {/* Verdict List */}
        <div className="space-y-2.5">
          {OPA_VERDICTS.map((v, i) => (
            <div
              key={i}
              className="flex flex-col md:flex-row md:items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-all gap-3 text-xs"
            >
              <div className="flex items-start md:items-center space-x-3">
                <span className="px-2 py-0.5 rounded font-mono font-bold bg-blue-500/15 text-blue-400 border border-blue-500/30 text-[10px] shrink-0">
                  {v.reg}
                </span>
                <code className="text-slate-400 font-mono text-[11px] shrink-0">{v.control}</code>
                <span className="text-slate-200 font-semibold">{v.title}</span>
              </div>

              <div className="flex items-center space-x-3 shrink-0">
                <span className="text-slate-400 text-[11px] max-w-md truncate" title={v.reason}>
                  {v.reason}
                </span>
                <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30 shrink-0">
                  {v.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
