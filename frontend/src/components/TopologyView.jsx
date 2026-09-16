import React, { useState } from 'react';
import { 
  Database, 
  Cpu, 
  ArrowRight, 
  RefreshCw, 
  ShieldCheck, 
  Server, 
  Layers, 
  Activity, 
  CheckCircle2, 
  FileCheck, 
  Lock, 
  Workflow, 
  Radio, 
  Sparkles,
  ChevronDown,
  ChevronUp,
  Boxes
} from 'lucide-react';
import { TOPOLOGY_SERVICES } from '../data/mockData';

export default function TopologyView() {
  const [showMicroservices, setShowMicroservices] = useState(false);

  return (
    <div className="space-y-8 animate-fade-in pb-10">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-slate-950 p-6 rounded-2xl border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute -right-10 -top-10 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -left-10 -bottom-10 w-48 h-48 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 space-y-1.5">
          <div className="flex items-center space-x-2.5">
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-extrabold uppercase tracking-wider bg-blue-500/20 text-blue-400 border border-blue-500/30">
              System Architecture
            </span>
            <span className="text-slate-500">&bull;</span>
            <span className="text-xs text-slate-400 font-mono">SecuriX SIH 2026 Core Engine</span>
          </div>
          <h2 className="text-xl md:text-2xl font-black tracking-tight text-white flex items-center gap-2">
            Two-Tier Cyber Risk Architecture
          </h2>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            Follow the <strong className="text-slate-200">Tier 1 Primary Flow</strong> left-to-right from ingestion to quantified delivery. The <strong className="text-slate-200">Tier 2 Foundation Band</strong> provides continuous pipeline security and platform primitives supporting every upper layer.
          </p>
        </div>

        <div className="relative z-10 flex items-center space-x-3 shrink-0">
          <button
            onClick={() => setShowMicroservices(!showMicroservices)}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800/90 hover:bg-slate-700 text-slate-200 border border-slate-700/80 transition-all flex items-center space-x-2 shadow-sm"
          >
            <Server className="w-3.5 h-3.5 text-blue-400" />
            <span>{showMicroservices ? 'Hide' : 'Inspect'} Microservice Ports</span>
            {showMicroservices ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TIER 1: THE PRIMARY FLOW (Large, Bolder, Numbered Arrows 1 -> 2 -> 3 -> 4) */}
      {/* ========================================================================= */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="flex h-2.5 w-2.5 rounded-full bg-blue-500 animate-pulse" />
            <span className="text-xs font-extrabold tracking-wider uppercase text-blue-400">
              Tier 1 — The Primary Flow (Left to Right)
            </span>
          </div>
          <span className="text-[11px] text-slate-500 font-medium hidden sm:inline">
            Sequential Risk Pipeline with Verification Feedback Loop
          </span>
        </div>

        {/* 4 Primary Flow Stations */}
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-4 items-stretch relative">
          
          {/* ----------------- BOX 1: SOURCES & INGESTION ----------------- */}
          <div className="relative flex flex-col justify-between rounded-2xl bg-gradient-to-b from-slate-900/95 via-slate-900/80 to-slate-950 border-2 border-blue-500/40 p-5 shadow-lg shadow-blue-500/5 hover:border-blue-500/70 transition-all group">
            {/* Corner Badge */}
            <div className="flex items-center justify-between mb-3">
              <span className="w-8 h-8 rounded-xl bg-blue-600/30 text-blue-400 border border-blue-500/40 flex items-center justify-center font-black text-sm shadow-inner">
                ①
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded-full border border-blue-500/20">
                Input
              </span>
            </div>

            <div className="space-y-3 flex-1">
              <div>
                <h3 className="font-extrabold text-base text-white group-hover:text-blue-300 transition-colors">
                  Sources &amp; Ingestion
                </h3>
                <div className="text-xs font-semibold text-blue-400/90 mt-0.5 italic">
                  &ldquo;Where signals come from&rdquo;
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80">
                <ul className="space-y-2 text-xs text-slate-300">
                  {[
                    { title: 'Source Code & Repos', note: 'Git commits & PR diffs' },
                    { title: 'Cloud Infrastructure', note: 'Terraform, K8s, IAM' },
                    { title: 'Wazuh (SIEM/XDR)', note: 'Host & agent alerts' },
                    { title: 'OpenVAS / Greenbone', note: 'CVE vulnerability feeds' },
                    { title: 'Apache Kafka', note: 'findings.raw bus' },
                    { title: 'Public Threat Feeds', note: 'NVD, CISA KEV, EPSS' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-blue-400 font-bold mt-0.5 text-xs">&bull;</span>
                      <div>
                        <span className="font-medium text-slate-200">{item.title}</span>
                        <span className="text-[10px] text-slate-400 block">{item.note}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Downward/Right Arrow Badge */}
            <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-blue-400 font-bold">
              <span>Streams to Kafka</span>
              <div className="flex items-center space-x-1">
                <span>1 &rarr; 2</span>
                <ArrowRight className="w-3.5 h-3.5 text-blue-400 animate-pulse" />
              </div>
            </div>
          </div>

          {/* ----------------- BOX 2: SHARED RISK KNOWLEDGE GRAPH ----------------- */}
          <div className="relative flex flex-col justify-between rounded-2xl bg-gradient-to-b from-slate-900/95 via-slate-900/80 to-slate-950 border-2 border-indigo-500/40 p-5 shadow-lg shadow-indigo-500/5 hover:border-indigo-500/70 transition-all group">
            <div className="flex items-center justify-between mb-3">
              <span className="w-8 h-8 rounded-xl bg-indigo-600/30 text-indigo-400 border border-indigo-500/40 flex items-center justify-center font-black text-sm shadow-inner">
                ②
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded-full border border-indigo-500/20">
                Core Hub
              </span>
            </div>

            <div className="space-y-3 flex-1">
              <div>
                <h3 className="font-extrabold text-base text-white group-hover:text-indigo-300 transition-colors">
                  Shared Risk Knowledge Graph
                </h3>
                <div className="text-xs font-semibold text-indigo-400/90 mt-0.5 italic">
                  &ldquo;Where everything gets connected&rdquo;
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80">
                <ul className="space-y-2.5 text-xs text-slate-300">
                  {[
                    { title: 'PostgreSQL + Apache AGE', note: 'Cypher graph engine (openCypher)' },
                    { title: 'pgvector', note: 'Semantic similarity & threat embeddings' },
                    { title: 'MinIO + Redis', note: 'Raw audit artifacts & memory cache' },
                    { title: 'Graph Query API', note: 'Unified multi-hop attack paths' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-indigo-400 font-bold mt-0.5 text-xs">&bull;</span>
                      <div>
                        <span className="font-medium text-slate-200">{item.title}</span>
                        <span className="text-[10px] text-slate-400 block">{item.note}</span>
                      </div>
                    </li>
                  ))}
                </ul>

                {/* Graph relations hint */}
                <div className="mt-4 p-2.5 rounded-xl bg-slate-950/80 border border-indigo-500/20 text-[10px] font-mono text-indigo-300 space-y-1">
                  <div className="text-slate-400 font-sans font-bold">Graph Relational Schema:</div>
                  <div>(Asset)-[:EXPOSES]-&gt;(Vuln)</div>
                  <div>(Vuln)-[:ENABLES]-&gt;(Threat)</div>
                  <div>(Threat)-[:PENALIZES]-&gt;(Impact ₹)</div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-indigo-400 font-bold">
              <span>Feeds Context</span>
              <div className="flex items-center space-x-1">
                <span>2 &rarr; 3</span>
                <ArrowRight className="w-3.5 h-3.5 text-indigo-400 animate-pulse" />
              </div>
            </div>
          </div>

          {/* ----------------- BOX 3: AI AGENT MESH + QUANTIFICATION LOOP ----------------- */}
          <div className="relative flex flex-col justify-between rounded-2xl bg-gradient-to-b from-slate-900/95 via-slate-900/80 to-slate-950 border-2 border-purple-500/50 p-5 shadow-lg shadow-purple-500/10 hover:border-purple-500/80 transition-all group">
            <div className="flex items-center justify-between mb-3">
              <span className="w-8 h-8 rounded-xl bg-purple-600/30 text-purple-400 border border-purple-500/40 flex items-center justify-center font-black text-sm shadow-inner">
                ③
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded-full border border-purple-500/20">
                Reasoning + Loop
              </span>
            </div>

            <div className="space-y-3 flex-1">
              <div>
                <h3 className="font-extrabold text-base text-white group-hover:text-purple-300 transition-colors">
                  AI Agent Mesh
                </h3>
                <div className="text-xs font-semibold text-purple-400/90 mt-0.5 italic">
                  &ldquo;Where risk gets reasoned about&rdquo;
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80">
                <ul className="space-y-2 text-xs text-slate-300">
                  {[
                    { title: 'Quantification Agent', note: 'FAIR Monte Carlo exposure simulator' },
                    { title: 'Compliance Agent', note: 'Rego policy evaluator (RBI, DPDP)' },
                    { title: 'Prioritization Agent', note: 'Graph centrality & asset tier weighting' },
                    { title: 'LangGraph', note: 'Multi-agent stateful workflow graphs' },
                    { title: 'LiteLLM', note: 'Multi-model fallback & privacy firewall' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-purple-400 font-bold mt-0.5 text-xs">&bull;</span>
                      <div>
                        <span className="font-medium text-slate-200">{item.title}</span>
                        <span className="text-[10px] text-slate-400 block">{item.note}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>

              {/* ----------------- QUANTIFICATION & VERIFICATION LOOP (FEEDS ③) ----------------- */}
              <div className="mt-3 p-3 rounded-xl bg-gradient-to-r from-purple-950/40 via-pink-950/30 to-purple-950/40 border border-pink-500/30 relative">
                <div className="flex items-center justify-between pb-1.5 border-b border-pink-500/20 mb-2">
                  <div className="flex items-center space-x-1.5 text-pink-400 font-bold text-[11px]">
                    <RefreshCw className="w-3.5 h-3.5 text-pink-400 animate-spin" style={{ animationDuration: '8s' }} />
                    <span>Quantification &amp; Verification</span>
                  </div>
                  <span className="text-[9px] font-extrabold uppercase tracking-wider text-pink-300 bg-pink-500/20 px-1.5 py-0.5 rounded">
                    ⟳ Feeds ③
                  </span>
                </div>

                <div className="text-[11px] font-semibold text-pink-300/90 italic mb-2">
                  &ldquo;Where risk becomes ₹ and gets proven&rdquo;
                </div>

                <div className="grid grid-cols-2 gap-1.5 text-[10px] text-slate-300">
                  <div className="bg-slate-900/80 px-2 py-1 rounded border border-slate-800">
                    <span className="font-bold text-pink-300">PyFair</span>
                    <span className="text-slate-400 block text-[9px]">Monte Carlo Loss</span>
                  </div>
                  <div className="bg-slate-900/80 px-2 py-1 rounded border border-slate-800">
                    <span className="font-bold text-pink-300">EPSS + DBIR</span>
                    <span className="text-slate-400 block text-[9px]">IBM/Verizon priors</span>
                  </div>
                  <div className="bg-slate-900/80 px-2 py-1 rounded border border-slate-800">
                    <span className="font-bold text-pink-300">OPA (Rego)</span>
                    <span className="text-slate-400 block text-[9px]">Policy evaluation</span>
                  </div>
                  <div className="bg-slate-900/80 px-2 py-1 rounded border border-slate-800">
                    <span className="font-bold text-pink-300">Dagger.io + Trivy</span>
                    <span className="text-slate-400 block text-[9px]">Reproducible gates</span>
                  </div>
                </div>

                <div className="mt-2 text-[9px] text-center text-pink-400 font-semibold flex items-center justify-center space-x-1">
                  <span>↕ Continuous Closed-Loop Feedback into Agent Mesh</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-purple-400 font-bold">
              <span>Exports Insights</span>
              <div className="flex items-center space-x-1">
                <span>3 &rarr; 4</span>
                <ArrowRight className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
              </div>
            </div>
          </div>

          {/* ----------------- BOX 4: DELIVERY LAYER ----------------- */}
          <div className="relative flex flex-col justify-between rounded-2xl bg-gradient-to-b from-slate-900/95 via-slate-900/80 to-slate-950 border-2 border-emerald-500/40 p-5 shadow-lg shadow-emerald-500/5 hover:border-emerald-500/70 transition-all group">
            <div className="flex items-center justify-between mb-3">
              <span className="w-8 h-8 rounded-xl bg-emerald-600/30 text-emerald-400 border border-emerald-500/40 flex items-center justify-center font-black text-sm shadow-inner">
                ④
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                Actionable Output
              </span>
            </div>

            <div className="space-y-3 flex-1">
              <div>
                <h3 className="font-extrabold text-base text-white group-hover:text-emerald-300 transition-colors">
                  Delivery Layer
                </h3>
                <div className="text-xs font-semibold text-emerald-400/90 mt-0.5 italic">
                  &ldquo;What the user actually sees&rdquo;
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80">
                <ul className="space-y-2 text-xs text-slate-300">
                  {[
                    { title: 'Grafana', note: 'Real-time financial exposure & SLA metrics' },
                    { title: 'Metabase', note: 'Self-service executive risk reporting' },
                    { title: 'Backstage Portal', note: 'Unified developer catalog & remediation' },
                    { title: 'Slack / Email', note: 'Targeted alerts with one-click fix PRs' },
                    { title: 'Evidence Pack', note: 'OpenTimestamps & Cosign cryptographic proof' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-emerald-400 font-bold mt-0.5 text-xs">&bull;</span>
                      <div>
                        <span className="font-medium text-slate-200">{item.title}</span>
                        <span className="text-[10px] text-slate-400 block">{item.note}</span>
                      </div>
                    </li>
                  ))}
                </ul>

                {/* Audit proof badge */}
                <div className="mt-4 p-2.5 rounded-xl bg-slate-950/80 border border-emerald-500/20 flex items-center space-x-2 text-[10px] text-emerald-300">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>Auditor-Ready: SHA-256 OTS digest signed with Cosign keyless PKI</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-emerald-400 font-bold">
              <span>Business Value</span>
              <span>₹ Quantified ROI</span>
            </div>
          </div>

        </div>
      </div>

      {/* ========================================================================= */}
      {/* DIVIDER & SUPPORT INDICATOR */}
      {/* ========================================================================= */}
      <div className="relative py-2 flex items-center justify-center">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t-2 border-dashed border-slate-700/80" />
        </div>
        <div className="relative px-4 py-1.5 rounded-full bg-slate-900 border border-slate-700 text-[11px] font-bold text-slate-300 flex items-center space-x-2 shadow-lg">
          <span className="text-cyan-400">▲</span>
          <span className="uppercase tracking-widest text-[10px] text-slate-400">
            Tier 2 Foundation Band (Supports &amp; Secures Every Step in Tier 1)
          </span>
          <span className="text-cyan-400">▲</span>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TIER 2: SUPPORTING / CROSS-CUTTING FOUNDATION (Smaller, distinct band)    */}
      {/* ========================================================================= */}
      <div className="p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800 shadow-2xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <div className="text-xs font-extrabold tracking-wider uppercase text-cyan-400 flex items-center space-x-2">
              <Boxes className="w-4 h-4" />
              <span>Tier 2 — Supporting &amp; Cross-Cutting Foundation</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              These shared capabilities do not come &ldquo;after&rdquo; Tier 1 — they run continuously underneath and secure all primary stages.
            </p>
          </div>
          <span className="px-2.5 py-1 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shrink-0">
            Unnumbered Support Band
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* ----------------- SUPPORT BOX A: CYBERSECURITY TOOLS ----------------- */}
          <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-cyan-500/40 transition-all space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <h4 className="font-extrabold text-sm text-slate-100">
                    Cybersecurity Tools — Open Source
                  </h4>
                </div>
                <div className="text-xs font-medium text-cyan-400/90 italic mt-0.5">
                  &ldquo;What secures the pipeline itself&rdquo;
                </div>
              </div>
              <span className="text-[10px] font-semibold text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                12 OSS Engines
              </span>
            </div>

            {/* 12 Open Source Security Tools Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
              {[
                { name: 'Semgrep', category: 'SAST Code Rules' },
                { name: 'Gitleaks', category: 'Secret Detection' },
                { name: 'Checkov', category: 'IaC Audit' },
                { name: 'tfsec', category: 'Terraform Security' },
                { name: 'Cosign / Sigstore', category: 'Image Signing' },
                { name: 'Coraza', category: 'WAF Engine' },
                { name: 'HashiCorp Vault', category: 'Secrets Broker' },
                { name: 'Cilium', category: 'eBPF Network Mesh' },
                { name: 'Suricata', category: 'Network IDS / PCAP' },
                { name: 'Zeek', category: 'Network Telemetry' },
                { name: 'Falco', category: 'Kernel eBPF Probe' },
                { name: 'OWASP ZAP', category: 'DAST API Scanner' },
              ].map((tool, i) => (
                <div 
                  key={i} 
                  className="p-2 rounded-lg bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 flex flex-col justify-between"
                >
                  <span className="font-bold text-slate-200 text-xs">{tool.name}</span>
                  <span className="text-[10px] text-slate-400 font-mono mt-0.5">{tool.category}</span>
                </div>
              ))}
            </div>
          </div>

          {/* ----------------- SUPPORT BOX B: CROSS-CUTTING PLATFORM SERVICES ----------------- */}
          <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-cyan-500/40 transition-all space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <h4 className="font-extrabold text-sm text-slate-100">
                    Cross-Cutting Platform Services
                  </h4>
                </div>
                <div className="text-xs font-medium text-cyan-400/90 italic mt-0.5">
                  &ldquo;What runs underneath everything&rdquo;
                </div>
              </div>
              <span className="text-[10px] font-semibold text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                Core Infra
              </span>
            </div>

            {/* 4 Pillars of Foundation Services */}
            <div className="space-y-2.5 text-xs">
              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start space-x-3">
                <Lock className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="font-bold text-slate-200">Identity &amp; Access</div>
                  <div className="text-slate-400 text-[11px]">
                    <strong className="text-amber-300">Keycloak</strong> — OpenID Connect (OIDC) SSO, RBAC roles (CISO, SecOps, Developer)
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start space-x-3">
                <Workflow className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="font-bold text-slate-200">Workflow Orchestration</div>
                  <div className="text-slate-400 text-[11px]">
                    <strong className="text-cyan-300">Temporal.io</strong> — Distributed state machines, resilient scan execution, retry isolation
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start space-x-3">
                <Server className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="font-bold text-slate-200">Infrastructure</div>
                  <div className="text-slate-400 text-[11px]">
                    <strong className="text-blue-300">Docker, Kubernetes &amp; Helm</strong> — Containerized microservices, high-availability deployments
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start space-x-3">
                <FileCheck className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="font-bold text-slate-200 flex items-center justify-between">
                    <span>CI/CD Security</span>
                    <span className="text-[9px] font-mono bg-emerald-500/20 text-emerald-400 px-1.5 py-0.2 rounded border border-emerald-500/30">
                      Workflow Verified
                    </span>
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    <strong className="text-emerald-300">GitHub Actions</strong> + Trivy / Gitleaks / Semgrep / Checkov automated pre-merge gates
                  </div>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>

      {/* ========================================================================= */}
      {/* COLLAPSIBLE MICROSERVICES RUNTIME STATUS                                  */}
      {/* ========================================================================= */}
      {showMicroservices && (
        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-5 space-y-4 animate-fade-in">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h4 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
                <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
                <span>Active Scanner Microservices &amp; Platform Ports</span>
              </h4>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Each scanner operates as an isolated FastAPI microservice with Kafka publisher and health probe endpoints.
              </p>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              10 Services Online
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
            {TOPOLOGY_SERVICES.map((s, i) => (
              <div
                key={i}
                className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/90 flex flex-col justify-between space-y-2 hover:border-slate-700 transition-all"
              >
                <div>
                  <div className="font-bold text-xs text-slate-100 truncate">{s.name}</div>
                  <div className="text-[10px] text-slate-400 truncate">{s.type}</div>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[10px]">
                  <span className="font-mono text-blue-400">:{s.port}</span>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    {s.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
