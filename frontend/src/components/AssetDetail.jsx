import React, { useState } from 'react';
import {
  Terminal,
  Wrench,
  CheckCircle2,
  ShieldAlert,
  FileText,
  Calculator,
  Cpu,
  Sparkles,
  Send,
  Copy,
  Check,
  Code2
} from 'lucide-react';
import { runOllamaChat, runOllamaRemediation } from '../services/api';

export default function AssetDetail({ finding, onToggleVerification, onGenerateEvidence }) {
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiSource, setAiSource] = useState(null);
  const [remediationCode, setRemediationCode] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [customPrompt, setCustomPrompt] = useState('');
  const [copied, setCopied] = useState(false);

  if (!finding) {
    return (
      <div className="glass-card rounded-2xl p-12 text-center text-slate-500 border border-slate-200">
        <ShieldAlert className="w-12 h-12 mx-auto text-slate-300 mb-3" />
        <p className="font-semibold text-slate-600">No finding selected</p>
        <p className="text-xs mt-1">Select a finding from the Risk Queue above to view its full trace, FAIR analysis, and Ollama reasoning.</p>
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

  // Run full Ollama security analysis
  const handleRunOllamaAnalysis = async () => {
    setAiLoading(true);
    setAiAnalysis(null);
    try {
      const prompt = `Perform a comprehensive cyber risk analysis on this finding: "${finding.title}" (Rule: ${finding.rule_id}) with ${finding.formatted_exposure_inr} annualized loss exposure. Detail the exact attack path, root cause, regulatory violations (RBI, SEBI, DPDP), and mitigation priority.`;
      const res = await runOllamaChat({ prompt, finding });
      if (res && res.content) {
        setAiAnalysis(res.content);
        setAiSource(res.source || 'ollama');
      }
    } catch (e) {
      console.error(e);
    } finally {
      setAiLoading(false);
    }
  };

  // Run Ollama code remediation
  const handleGenerateOllamaPatch = async () => {
    setRemediationLoading(true);
    try {
      const res = await runOllamaRemediation({ finding });
      if (res && res.content) {
        setRemediationCode(res.content);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setRemediationLoading(false);
    }
  };

  // Custom question to Ollama
  const handleSendCustomPrompt = async (e) => {
    e.preventDefault();
    if (!customPrompt.trim()) return;
    setAiLoading(true);
    const q = customPrompt;
    setCustomPrompt('');
    try {
      const res = await runOllamaChat({ prompt: q, finding });
      if (res && res.content) {
        setAiAnalysis(res.content);
        setAiSource(res.source || 'ollama');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setAiLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
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

      {/* ── OLLAMA AI ASSISTANT & AUTOMATED REMEDIATION ENGINE ── */}
      <div className="p-5 rounded-2xl bg-gradient-to-br from-indigo-50/70 via-white to-purple-50/70 border border-indigo-100 shadow-sm space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <div className="p-2 rounded-xl bg-indigo-600 text-white shadow-md shadow-indigo-600/20">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-950 flex items-center space-x-1.5">
                <span>AI Cyber Risk Analyst</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-indigo-100 text-indigo-700">
                  Ollama Native / Heuristics
                </span>
              </h4>
              <p className="text-[11px] text-slate-500">Autonomous risk reasoning, threat vector modeling, and verified patch synthesis</p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleRunOllamaAnalysis}
              disabled={aiLoading}
              className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white shadow-md shadow-indigo-600/20 transition-all flex items-center space-x-1.5 disabled:opacity-50"
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>{aiLoading ? 'Ollama Analyzing...' : 'Analyze with Ollama'}</span>
            </button>

            <button
              onClick={handleGenerateOllamaPatch}
              disabled={remediationLoading}
              className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-purple-600 hover:bg-purple-500 text-white shadow-md shadow-purple-600/20 transition-all flex items-center space-x-1.5 disabled:opacity-50"
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>{remediationLoading ? 'Generating Fix...' : 'Generate Patch'}</span>
            </button>
          </div>
        </div>

        {/* AI Analysis Output */}
        {aiAnalysis && (
          <div className="p-4 rounded-xl bg-white/90 border border-indigo-200/80 shadow-sm space-y-2 text-xs">
            <div className="flex items-center justify-between text-indigo-900 font-semibold border-b pb-2">
              <span className="flex items-center space-x-1.5">
                <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
                <span>Ollama Cyber Analysis ({aiSource || 'live model'})</span>
              </span>
              <button
                onClick={() => copyToClipboard(aiAnalysis)}
                className="text-slate-400 hover:text-slate-600 flex items-center space-x-1"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="text-slate-800 leading-relaxed whitespace-pre-wrap font-sans text-xs">
              {aiAnalysis}
            </div>
          </div>
        )}

        {/* Code Remediation Output */}
        {remediationCode && (
          <div className="p-4 rounded-xl bg-slate-900 text-slate-100 border border-slate-800 shadow-sm space-y-2 text-xs">
            <div className="flex items-center justify-between text-purple-300 font-semibold border-b border-slate-800 pb-2">
              <span className="flex items-center space-x-1.5">
                <Code2 className="w-3.5 h-3.5 text-purple-400" />
                <span>Verified Remediation Patch</span>
              </span>
              <button
                onClick={() => copyToClipboard(remediationCode)}
                className="text-slate-400 hover:text-white flex items-center space-x-1"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Patch'}</span>
              </button>
            </div>
            <pre className="font-mono text-[11px] leading-relaxed overflow-x-auto whitespace-pre-wrap text-emerald-400">
              {remediationCode}
            </pre>
          </div>
        )}

        {/* Interactive Ask Ollama Input */}
        <form onSubmit={handleSendCustomPrompt} className="flex items-center space-x-2 pt-1">
          <input
            type="text"
            value={customPrompt}
            onChange={(e) => setCustomPrompt(e.target.value)}
            placeholder={`Ask Ollama about this ${finding.tool} vulnerability, exploit chain, or RBI compliance...`}
            className="flex-1 px-4 py-2 text-xs rounded-xl bg-white border border-indigo-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 shadow-sm text-slate-800"
          />
          <button
            type="submit"
            disabled={aiLoading || !customPrompt.trim()}
            className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold shadow-md shadow-indigo-600/20 disabled:opacity-50 flex items-center space-x-1"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send</span>
          </button>
        </form>
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
            <span>Standard Remediation Advice</span>
          </div>
          <div className="text-slate-700 leading-relaxed bg-white p-3 rounded-lg border border-slate-200">
            {finding.remediation || 'Remediate according to security guidelines.'}
          </div>
        </div>
      </div>
    </div>
  );
}
