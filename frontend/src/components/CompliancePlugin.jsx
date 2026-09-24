import React from 'react';
import { Scale, CheckCircle2, XCircle } from 'lucide-react';
import { COMPLIANCE_REGULATIONS, OPA_VERDICTS } from '../data/mockData';

export default function CompliancePlugin() {
  return (
    <div className="space-y-6">
      {/* Overview Cards by Regulation */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {COMPLIANCE_REGULATIONS.map((c) => (
          <div key={c.reg} className="glass-card glass-card-hover rounded-2xl p-4 border border-slate-200 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-black text-blue-600 font-mono tracking-wider">{c.reg}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${c.score >= 85 ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                  {c.score}%
                </span>
              </div>
              <div className="text-xs font-semibold text-slate-800 mt-2 line-clamp-1" title={c.name}>
                {c.name}
              </div>
              <div className="text-[10px] text-slate-400 truncate mt-0.5">{c.authority}</div>
            </div>

            <div className="flex items-center justify-between text-[11px] mt-4 pt-3 border-t border-slate-200 font-mono">
              <span className="text-emerald-600 font-bold flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3" />
                <span>{c.pass} Pass</span>
              </span>
              <span className="text-red-500 font-bold flex items-center space-x-1">
                <XCircle className="w-3 h-3" />
                <span>{c.fail} Fail</span>
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* OPA Rego Policy Enforcement Verdicts */}
      <div className="glass-card rounded-2xl p-6 border border-slate-200 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
              <Scale className="w-4 h-4 text-blue-500" />
              <span>Open Policy Agent (OPA) Rego Enforcement Engine</span>
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Automated compliance evaluations running OPA policies against Apache AGE findings
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500 bg-slate-100 px-3 py-1 rounded-lg">
            OPA Evaluated: 6 Controls Failed
          </span>
        </div>

        {/* Verdict List */}
        <div className="space-y-2.5">
          {OPA_VERDICTS.map((v, i) => (
            <div
              key={i}
              className="flex flex-col md:flex-row md:items-center justify-between p-4 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-300 transition-all gap-3 text-xs"
            >
              <div className="flex items-start md:items-center space-x-3">
                <span className="px-2 py-0.5 rounded font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200 text-[10px] shrink-0">
                  {v.reg}
                </span>
                <code className="text-slate-500 font-mono text-[11px] shrink-0">{v.control}</code>
                <span className="text-slate-800 font-semibold">{v.title}</span>
              </div>

              <div className="flex items-center space-x-3 shrink-0">
                <span className="text-slate-400 text-[11px] max-w-md truncate" title={v.reason}>
                  {v.reason}
                </span>
                <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-red-50 text-red-600 border border-red-200 shrink-0">
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
