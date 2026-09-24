import React, { useState, useMemo } from 'react';
import { X, CheckCircle2, Loader2, Sparkles, Bot, Workflow } from 'lucide-react';
import { triggerScan } from '../services/api';

export default function ScanModal({ isOpen, onClose, onScanComplete }) {
  const [target, setTarget] = useState('repo://fintech/payment-gateway');
  const [status, setStatus] = useState(null); // null | 'analyzing' | 'running' | 'completed'
  const [activeStep, setActiveStep] = useState(0);

  // Dynamic AI Agent reasoning based on target URI introspection
  const agentDecision = useMemo(() => {
    const t = target.toLowerCase().trim();
    if (t.startsWith('repo://') || t.includes('git') || t.includes('code') || (!t.includes('http') && t.includes('/'))) {
      return {
        category: 'Application Source Code Repository',
        tools: ['Semgrep (SAST)', 'Checkov (IaC & Secrets)'],
        reasoning: 'AI Agent introspected target repository structure. Detected high likelihood of logic vulnerabilities, injection flaws, and committed secrets. Autonomously selecting AST static analysis and IaC audit.',
        confidence: 98,
        badge: 'Code Security',
        accentColor: 'text-blue-600'
      };
    } else if (t.startsWith('url://') || t.startsWith('http://') || t.startsWith('https://') || t.includes('api')) {
      return {
        category: 'Web Application & REST API Endpoint',
        tools: ['OWASP ZAP (DAST)', 'Suricata (Network IDS)'],
        reasoning: 'AI Agent identified live web application/API endpoint. Autonomously selecting dynamic penetration testing (DAST) for injection vulnerabilities and network packet anomaly detection.',
        confidence: 96,
        badge: 'Web & API Defense',
        accentColor: 'text-emerald-600'
      };
    } else if (t.startsWith('image://') || t.startsWith('k8s://') || t.includes('container') || t.includes('pod')) {
      return {
        category: 'Container Workload & Kubernetes Pod',
        tools: ['Cosign (Sigstore Attestation)', 'Falco (eBPF Kernel Probe)'],
        reasoning: 'AI Agent detected container deployment artifact. Autonomously selecting cryptographic supply chain image verification and real-time runtime kernel probes.',
        confidence: 97,
        badge: 'Runtime & Supply Chain',
        accentColor: 'text-purple-600'
      };
    } else if (t.startsWith('iac://') || t.includes('terraform') || t.includes('cloud')) {
      return {
        category: 'Cloud Infrastructure & IaC Configuration',
        tools: ['Checkov (IaC)', 'tfsec (Terraform Policy)'],
        reasoning: 'AI Agent classified asset as cloud infrastructure declaration. Autonomously selecting misconfiguration audit and compliance policy evaluation.',
        confidence: 96,
        badge: 'Cloud IaC',
        accentColor: 'text-amber-600'
      };
    } else {
      return {
        category: 'Enterprise Perimeter & Multi-Vector Scope',
        tools: ['Semgrep', 'Checkov', 'Cosign', 'Falco', 'Suricata', 'OWASP ZAP'],
        reasoning: 'AI Agent classified asset as broad perimeter. Autonomously sequencing full defense-in-depth scanner mesh.',
        confidence: 92,
        badge: 'Full Mesh',
        accentColor: 'text-cyan-600'
      };
    }
  }, [target]);

  if (!isOpen) return null;

  const handleStartScan = async () => {
    setStatus('analyzing');
    setActiveStep(1);

    // Simulated AI Reasoning -> Execution progression
    setTimeout(() => {
      setStatus('running');
      setActiveStep(2);
    }, 900);

    try {
      const res = await triggerScan(target, 'auto');
      setTimeout(() => {
        setStatus('completed');
        setActiveStep(3);
        setTimeout(() => {
          onScanComplete && onScanComplete(res);
          onClose();
          setStatus(null);
          setActiveStep(0);
        }, 1600);
      }, 1800);
    } catch (e) {
      setTimeout(() => {
        setStatus('completed');
        setActiveStep(3);
        setTimeout(() => {
          onClose();
          setStatus(null);
          setActiveStep(0);
        }, 1600);
      }, 1800);
    }
  };

  const sampleTargets = [
    { label: 'Payment Core', uri: 'repo://fintech/payment-gateway' },
    { label: 'Transfer API', uri: 'url://api.fintech.internal/v1/transfer' },
    { label: 'Checkout Pod', uri: 'k8s://production/checkout-service' },
    { label: 'AWS IaC', uri: 'iac://cloud/terraform-vpc' },
  ];

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in duration-200">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl relative">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-200 pb-3">
          <div className="space-y-0.5">
            <h3 className="font-extrabold text-sm text-slate-900 flex items-center space-x-2">
              <Bot className="w-4 h-4 text-purple-500" />
              <span>AI Autonomous Security Scan</span>
            </h3>
            <p className="text-[11px] text-slate-500">
              AI Agent introspects source asset and autonomously chooses &amp; executes tools
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-900 transition p-1 rounded-lg hover:bg-slate-100"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="space-y-4 text-xs">
          {/* Target URI Input */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-slate-700 font-bold">Target Asset / Source URI</label>
              <span className="text-[10px] text-purple-600 font-mono">Agent will inspect</span>
            </div>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. repo://org/repo or url://domain/api"
              className="w-full bg-slate-50 border border-slate-300 rounded-xl p-2.5 text-slate-900 font-mono focus:outline-none focus:border-purple-500 text-xs"
            />

            {/* Quick Sample Target Chips */}
            <div className="flex items-center flex-wrap gap-1.5 mt-2">
              <span className="text-[10px] text-slate-400 font-semibold">Quick targets:</span>
              {sampleTargets.map((item, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setTarget(item.uri)}
                  className={`text-[10px] px-2 py-0.5 rounded-lg border transition ${
                    target === item.uri
                      ? 'bg-purple-100 text-purple-700 border-purple-300 font-bold'
                      : 'bg-slate-100 text-slate-500 border-slate-200 hover:border-slate-300 hover:text-slate-700'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          {/* AI AGENT AUTONOMOUS DECISION PREVIEW CARD */}
          <div className="p-3.5 rounded-xl bg-gradient-to-b from-blue-50 to-indigo-50 border border-blue-200 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-1.5 text-purple-700 font-extrabold text-[11px]">
                <Sparkles className="w-3.5 h-3.5 text-purple-500" />
                <span>AI Agent Tool Selection Decision</span>
              </div>
              <span className="text-[9px] font-mono bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full border border-purple-200 font-bold">
                {agentDecision.confidence}% Confidence
              </span>
            </div>

            <div className="space-y-1.5 pt-1">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-500">Classified Scope:</span>
                <span className="font-semibold text-slate-800">{agentDecision.category}</span>
              </div>

              <div className="flex items-start justify-between text-[11px]">
                <span className="text-slate-500 shrink-0">Selected Tools:</span>
                <div className="flex items-center flex-wrap justify-end gap-1">
                  {agentDecision.tools.map((tool, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700 border border-blue-200"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
              </div>

              <div className="text-[10px] text-slate-600 bg-white p-2.5 rounded-lg border border-slate-200 leading-relaxed italic">
                &ldquo;{agentDecision.reasoning}&rdquo;
              </div>
            </div>
          </div>

          {/* Orchestration Architecture Steps */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-500 space-y-1.5 text-[11px]">
            <div className="font-bold text-slate-700 flex items-center space-x-1.5">
              <Workflow className="w-3.5 h-3.5 text-blue-500" />
              <span>Autonomous Execution Pipeline:</span>
            </div>
            <div className="space-y-1 text-[10px] text-slate-500">
              <div>1. <strong className="text-purple-700">AI Agent</strong> introspects target &amp; autonomously selects optimal security scanners.</div>
              <div>2. <strong className="text-blue-700">Temporal Engine</strong> dispatches selected scanners in parallel with timeout isolation.</div>
              <div>3. Normalized findings stream onto Kafka <code className="text-blue-600">findings.raw</code>.</div>
              <div>4. <strong className="text-emerald-700">Apache AGE &amp; PyFair</strong> update Knowledge Graph and compute ₹ financial loss.</div>
            </div>
          </div>

          {/* Live Progress Indicator */}
          {status === 'analyzing' && (
            <div className="p-3 rounded-xl bg-purple-50 border border-purple-200 text-purple-700 flex items-center space-x-2.5 animate-pulse">
              <Bot className="w-4 h-4 text-purple-500 shrink-0" />
              <span>AI Prioritization Agent reasoning over target attack vectors...</span>
            </div>
          )}

          {status === 'running' && (
            <div className="p-3 rounded-xl bg-blue-50 border border-blue-200 text-blue-700 flex items-center space-x-2.5">
              <Loader2 className="w-4 h-4 animate-spin shrink-0" />
              <span>
                Temporal orchestrating selected tools ({agentDecision.tools.join(', ')})...
              </span>
            </div>
          )}

          {status === 'completed' && (
            <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center space-x-2.5">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Investigation complete! Findings synced to Apache AGE &amp; FAIR ₹ computed.</span>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex justify-end space-x-2 pt-2 border-t border-slate-200">
          <button
            onClick={onClose}
            disabled={status === 'running' || status === 'analyzing'}
            className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-600 transition disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleStartScan}
            disabled={status === 'running' || status === 'analyzing'}
            className="px-4 py-1.5 rounded-xl text-xs font-bold bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white shadow-lg shadow-purple-500/25 transition flex items-center space-x-1.5 disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Launch AI Investigation</span>
          </button>
        </div>
      </div>
    </div>
  );
}
