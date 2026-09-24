import React from 'react';
import {
  Terminal,
  Wrench,
  CheckCircle2,
  ShieldAlert,
  FileText,
  Calculator
} from 'lucide-react';

export default function AssetDetail({ finding, onToggleVerification, onGenerateEvidence }) {
  if (!finding) {
    return (
      <div className="glass-card rounded-2xl p-12 text-center text-slate-500 border border-slate-200">
        <ShieldAlert className="w-12 h-12 mx-auto text-slate-300 mb-3" />
        <p className="font-semibold text-slate-600">No finding selected</p>
        <p className="text-xs mt-1">Select a finding from the Risk Queue above to view its full trace and FAIR analysis.</p>
      </div>
    );
  }

  const fair = finding.fair_breakdown || {
    loss_event_frequency: 0.5,
    loss_magnitude_inr: 5000000,
    primary_loss_inr: 2000000,
    secondary_loss_inr: 1500000,
    formatted_inr: finding.formatted_exposure_inr
  };

  return (
    <div className="glass-card rounded-2xl p-6 space-y-6 border border-slate-200">
      {/* Top Details & Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 pb-5">
        <div className="space-y-1.5 max-w-2xl">
          <div className="flex items-center space-x-2">
            <span className="px-2.5 py-0.5 rounded-lg text-[10px] font-bold uppercase bg-red-50 text-red-600 border border-red-200">
              {finding.severity || 'high'}
            </span>
            <span className="px-2.5 py-0.5 rounded-lg text-[10px] font-bold uppercase bg-blue-50 text-blue-700 border border-blue-200">
              Detected by {finding.tool}
            </span>
            <span className="px-2.5 py-0.5 rounded-lg text-[10px] font-mono font-semibold bg-slate-100 text-slate-500">
              Rule: {finding.rule_id}
            </span>
          </div>

          <h3 className="text-lg font-extrabold text-slate-900 tracking-tight">
            {finding.title}
          </h3>

          <p className="text-xs text-slate-500 font-mono">
            Target Asset: <span className="text-blue-600 font-semibold">{finding.asset_id}</span>
          </p>
        </div>

        {/* Right exposure & Action */}
        <div className="text-right space-y-2">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
            Annualized Loss Exposure (ALE)
          </div>
          <div className="text-3xl font-black text-red-600 font-mono">
            {finding.formatted_exposure_inr}
          </div>

          <div className="flex items-center justify-end space-x-2 pt-1">
            <button
              onClick={() => onToggleVerification(finding.finding_id)}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
                finding.verified
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-blue-600 text-white border-blue-500 hover:bg-blue-500 shadow-md shadow-blue-500/25'
              }`}
            >
              {finding.verified ? (
                <span className="flex items-center space-x-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Verified by SecOps</span>
                </span>
              ) : (
                <span>Mark as Verified</span>
              )}
            </button>

            <button
              onClick={onGenerateEvidence}
              className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 transition-all flex items-center space-x-1.5"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Evidence</span>
            </button>
          </div>
        </div>
      </div>

      {/* FAIR Quantitative Breakdown (₹) */}
      <div className="space-y-3">
        <div className="flex items-center space-x-2">
          <Calculator className="w-4 h-4 text-blue-500" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
            PyFair Quantitative Breakdown (₹ Indian Rupees)
          </h4>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
          {/* LEF */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
            <div className="text-slate-500 text-[11px] font-sans">Loss Event Frequency (LEF)</div>
            <div className="text-lg font-bold text-slate-900 mt-1">
              {fair.loss_event_frequency} <span className="text-xs text-slate-400 font-sans">events/year</span>
            </div>
            <div className="text-[10px] text-slate-400 font-sans mt-1">Threat event rate &times; Vulnerability %</div>
          </div>

          {/* Primary Loss */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
            <div className="text-slate-500 text-[11px] font-sans">Primary Loss (Response & Fix)</div>
            <div className="text-lg font-bold text-slate-900 mt-1">
              ₹{(fair.primary_loss_inr || 0).toLocaleString('en-IN')}
            </div>
            <div className="text-[10px] text-slate-400 font-sans mt-1">Incident response, forensics, patching</div>
          </div>

          {/* Secondary Loss */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
            <div className="text-slate-500 text-[11px] font-sans">Secondary Loss (Fines & Frictions)</div>
            <div className="text-lg font-bold text-slate-900 mt-1">
              ₹{(fair.secondary_loss_inr || 0).toLocaleString('en-IN')}
            </div>
            <div className="text-[10px] text-slate-400 font-sans mt-1">Regulatory penalties (RBI/DPDP) & legal</div>
          </div>

          {/* Expected Annual Loss */}
          <div className="p-4 rounded-xl bg-red-50 border border-red-200">
            <div className="text-red-600 text-[11px] font-sans font-semibold">Annual Loss Exposure (ALE)</div>
            <div className="text-lg font-bold text-red-600 mt-1">
              {finding.formatted_exposure_inr}
            </div>
            <div className="text-[10px] text-slate-500 font-sans mt-1">Monte Carlo 10,000-run median</div>
          </div>
        </div>
      </div>

      {/* Raw Scanner Tool Evidence & Recommended Remediation */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
        {/* Raw Evidence */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
          <div className="font-bold text-slate-800 flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-blue-500" />
            <span>Raw Scanner Evidence ({finding.tool})</span>
          </div>
          <pre className="font-mono text-slate-600 text-[11px] p-3 rounded-lg bg-white overflow-x-auto whitespace-pre-wrap border border-slate-200">
            {finding.evidence || 'No raw output attached for this finding.'}
          </pre>
        </div>

        {/* Recommended Remediation */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
          <div className="font-bold text-slate-800 flex items-center space-x-2">
            <Wrench className="w-4 h-4 text-emerald-500" />
            <span>Remediation Advice</span>
          </div>
          <div className="text-slate-700 leading-relaxed bg-white p-3 rounded-lg border border-slate-200">
            {finding.remediation || 'Remediate according to security guidelines.'}
          </div>
        </div>
      </div>
    </div>
  );
}
