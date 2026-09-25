import React, { useState, useEffect } from 'react';
import { Scale, CheckCircle2, XCircle, ShieldAlert } from 'lucide-react';
import { fetchComplianceSummary } from '../services/api';

export default function CompliancePlugin() {
  const [frameworks, setFrameworks] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      setLoading(true);
      const summary = await fetchComplianceSummary();
      if (summary && summary.frameworks) {
        setFrameworks(summary.frameworks);
      }
      setLoading(false);
    }
    load();
  }, []);

  const frameworkList = Object.entries(frameworks).map(([key, data]) => ({
    reg: key,
    name: data.name || key,
    score: data.score !== undefined ? data.score : 80,
    pass: data.pass || 0,
    fail: data.fail || 0,
    authority:
      key === 'RBI'
        ? 'Reserve Bank of India'
        : key === 'SEBI'
        ? 'Securities and Exchange Board of India'
        : key === 'DPDP'
        ? 'Ministry of Electronics and IT'
        : key === 'CERT-In'
        ? 'Indian Computer Emergency Response Team'
        : key === 'ISO27001'
        ? 'ISO/IEC'
        : 'National Institute of Standards'
  }));

  return (
    <div className="space-y-6">
      {/* Overview Cards by Regulation */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        {frameworkList.length === 0 ? (
          <div className="col-span-full p-6 text-center text-slate-400 text-xs bg-white rounded-2xl border border-slate-200">
            {loading ? 'Evaluating live OPA policies against findings...' : 'No compliance framework data available.'}
          </div>
        ) : (
          frameworkList.map((c) => (
            <div key={c.reg} className="glass-card glass-card-hover rounded-2xl p-4 border border-slate-200 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-black text-blue-600 font-mono tracking-wider">{c.reg}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${c.score >= 80 ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
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
          ))
        )}
      </div>

      {/* OPA Rego Policy Enforcement Verdicts */}
      <div className="glass-card rounded-2xl p-6 border border-slate-200 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
              <Scale className="w-4 h-4 text-blue-500" />
              <span>Open Policy Agent (OPA) Rego Enforcement Engine (Live)</span>
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Live evaluations calculated by OPA engine across RBI, SEBI, ISO 27001, NIST CSF, and DPDP policies
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500 bg-slate-100 px-3 py-1 rounded-lg flex items-center space-x-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-blue-500" />
            <span>OPA Engine: Live Evaluated</span>
          </span>
        </div>

        {/* Verdicts */}
        <div className="space-y-2.5">
          {frameworkList.map((f, i) => (
            <div
              key={i}
              className="flex flex-col md:flex-row md:items-center justify-between p-4 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-300 transition-all gap-3 text-xs"
            >
              <div className="flex items-start md:items-center space-x-3">
                <span className="px-2 py-0.5 rounded font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200 text-[10px] shrink-0">
                  {f.reg}
                </span>
                <span className="text-slate-800 font-semibold">{f.name}</span>
              </div>

              <div className="flex items-center space-x-3 shrink-0">
                <span className="text-slate-500 text-[11px]">
                  {f.fail} non-compliant findings detected
                </span>
                <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${f.score >= 80 ? 'bg-emerald-50 text-emerald-600 border border-emerald-200' : 'bg-red-50 text-red-600 border border-red-200'} shrink-0`}>
                  {f.score >= 80 ? 'COMPLIANT' : 'NEEDS_REMEDIATION'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
