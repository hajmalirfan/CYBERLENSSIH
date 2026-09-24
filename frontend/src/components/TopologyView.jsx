import React, { useState } from 'react';
import {
  Cpu,
  ArrowRight,
  RefreshCw,
  ShieldCheck,
  Server,
  Layers,
  CheckCircle2,
  FileCheck,
  Lock,
  Workflow,
  Radio,
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
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-white via-slate-50 to-slate-100 p-6 rounded-2xl border border-slate-200 shadow-sm relative overflow-hidden">
        <div className="absolute -right-10 -top-10 w-48 h-48 bg-blue-100 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -left-10 -bottom-10 w-48 h-48 bg-purple-100 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 space-y-1.5">
          <div className="flex items-center space-x-2.5">
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-extrabold uppercase tracking-wider bg-blue-100 text-blue-700 border border-blue-200">
              System Architecture
            </span>
            <span className="text-slate-300">&bull;</span>
            <span className="text-xs text-slate-500 font-mono">CYBERLENS SIH 2026 Core Engine</span>
          </div>
          <h2 className="text-xl md:text-2xl font-black tracking-tight text-slate-900 flex items-center gap-2">
            Two-Tier Cyber Risk Architecture
          </h2>
          <p className="text-xs text-slate-500 max-w-3xl leading-relaxed">
            Follow the <strong className="text-slate-800">Tier 1 Primary Flow</strong> left-to-right from ingestion to quantified delivery. The <strong className="text-slate-800">Tier 2 Foundation Band</strong> provides continuous pipeline security and platform primitives supporting every upper layer.
          </p>
        </div>

        <div className="relative z-10 flex items-center space-x-3 shrink-0">
          <button
            onClick={() => setShowMicroservices(!showMicroservices)}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 transition-all flex items-center space-x-2 shadow-sm"
          >
            <Server className="w-3.5 h-3.5 text-blue-500" />
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
            <span className="text-xs font-extrabold tracking-wider uppercase text-blue-600">
              Tier 1 — The Primary Flow (Left to Right)
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-medium hidden sm:inline">
            Sequential Risk Pipeline with Verification Feedback Loop
          </span>
        </div>

        {/* 4 Primary Flow Stations */}
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-4 items-stretch relative">

          {/* ----------------- BOX 1: SOURCES & INGESTION ----------------- */}
          <div className="relative flex flex-col justify-between rounded-2xl bg-white border-2 border-blue-200 p-5 shadow-sm hover:border-blue-400 transition-all group">
            {/* Corner Badge */}
            <div className="flex items-center justify-between mb-3">
              <span className="w-8 h-8 rounded-xl bg-blue-100 text-blue-700 border border-blue-200 flex items-center justify-center font-black text-sm">
                ①
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-blue-700 bg-blue-50 px-2 py-0.5 rounded-full border border-blue-200">
                Input
              </span>
            </div>

            <div className="space-y-3 flex-1">
              <div>
                <h3 className="font-extrabold text-base text-slate-900 group-hover:text-blue-600 transition-colors">
                  Sources &amp; Ingestion
                </h3>
                <div className="text-xs font-semibold text-blue-600 mt-0.5 italic">
                  &ldquo;Where signals come from&rdquo;
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200">
                <ul className="space-y-2 text-xs text-slate-600">
                  {[
                    { title: 'Source Code & Repos', note: 'Git commits & PR diffs' },
                    { title: 'Cloud Infrastructure', note: 'Terraform, K8s, IAM' },
                    { title: 'Wazuh (SIEM/XDR)', note: 'Host & agent alerts' },
                    { title: 'OpenVAS / Greenbone', note: 'CVE vulnerability feeds' },
                    { title: 'Apache Kafka', note: 'findings.raw bus' },
                    { title: 'Public Threat Feeds', note: 'NVD, CISA KEV, EPSS' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-blue-500 font-bold mt-0.5 text-xs">&bull;</span>
                      <div>
                        <span className="font-medium text-slate-800">{item.title}</span>
                        <span className="text-[10px] text-slate-500 block">{item.note}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Downward/Right Arrow Badge */}
            <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] text-blue-600 font-bold">
              <span>Streams to Kafka</span>
              <div className="flex items-center space-x-1">
                <span>1 &rarr; 2</span>
                <ArrowRight className="w-3.5 h-3.5 text-blue-500 animate-pulse" />
              </div>
            </div>
          </div>

          {/* ----------------- BOX 2: SHARED RISK KNOWLEDGE GRAPH ----------------- */}
          <div className="relative flex flex-col justify-between rounded-2xl bg-white border-2 border-indigo-200 p-5 shadow-sm hover:border-indigo-400 transition-all group">
            <div className="flex items-center justify-between mb-3">
              <span className="w-8 h-8 rounded-xl bg-indigo-100 text-indigo-700 border border-indigo-200 flex items-center justify-center font-black text-sm">
                ②
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-full border border-indigo-200">
                Core Hub
              </span>
            </div>

            <div className="space-y-3 flex-1">
              <div>
                <h3 className="font-extrabold text-base text-slate-900 group-hover:text-indigo-600 transition-colors">
                  Shared Risk Knowledge Graph
                </h3>
                <div className="text-xs font-semibold text-indigo-600 mt-0.5 italic">
                  &ldquo;Where everything gets connected&rdquo;
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200">
                <ul className="space-y-2.5 text-xs text-slate-600">
                  {[
                    { title: 'PostgreSQL + Apache AGE', note: 'Cypher graph engine (openCypher)' },
                    { title: 'pgvector', note: 'Semantic similarity & threat embeddings' },
                    { title: 'MinIO + Redis', note: 'Raw audit artifacts & memory cache' },
                    { title: 'Graph Query API', note: 'Unified multi-hop attack paths' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-indigo-500 font-bold mt-0.5 text-xs">&bull;</span>
                      <div>
                        <span className="font-medium text-slate-800">{item.title}</span>
                        <span className="text-[10px] text-slate-500 block">{item.note}</span>
                      </div>
                    </li>
                  ))}
                </ul>

                {/* Graph relations hint */}
                <div className="mt-4 p-2.5 rounded-xl bg-slate-50 border border-indigo-200 text-[10px] font-mono text-indigo-700 space-y-1">
                  <div className="text-slate-500 font-sans font-bold">Graph Relational Schema:</div>
                  <div>(Asset)-[:EXPOSES]-&gt;(Vuln)</div>
                  <div>(Vuln)-[:ENABLES]-&gt;(Threat)</div>
                  <div>(Threat)-[:PENALIZES]-&gt;(Impact ₹)</div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] text-indigo-600 font-bold">
              <span>Feeds Context</span>
              <div className="flex items-center space-x-1">
                <span>2 &rarr; 3</span>
                <ArrowRight className="w-3.5 h-3.5 text-indigo-500 animate-pulse" />
              </div>
            </div>
          </div>

          {/* ----------------- BOX 3: AI AGENT MESH + QUANTIFICATION LOOP ----------------- */}
          <div className="relative flex flex-col justify-between rounded-2xl bg-white border-2 border-purple-300 p-5 shadow-sm hover:border-purple-400 transition-all group">
            <div className="flex items-center justify-between mb-3">
              <span className="w-8 h-8 rounded-xl bg-purple-100 text-purple-700 border border-purple-200 flex items-center justify-center font-black text-sm">
                ③
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-purple-700 bg-purple-50 px-2 py-0.5 rounded-full border border-purple-200">
                Reasoning + Loop
              </span>
            </div>

            <div className="space-y-3 flex-1">
              <div>
                <h3 className="font-extrabold text-base text-slate-900 group-hover:text-purple-600 transition-colors">
                  AI Agent Mesh
                </h3>
                <div className="text-xs font-semibold text-purple-600 mt-0.5 italic">
                  &ldquo;Where risk gets reasoned about&rdquo;
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200">
                <ul className="space-y-2 text-xs text-slate-600">
                  {[
                    { title: 'Quantification Agent', note: 'FAIR Monte Carlo exposure simulator' },
                    { title: 'Compliance Agent', note: 'Rego policy evaluator (RBI, DPDP)' },
                    { title: 'Prioritization Agent', note: 'Graph centrality & asset tier weighting' },
                    { title: 'LangGraph', note: 'Multi-agent stateful workflow graphs' },
                    { title: 'LiteLLM', note: 'Multi-model fallback & privacy firewall' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-purple-500 font-bold mt-0.5 text-xs">&bull;</span>
                      <div>
                        <span className="font-medium text-slate-800">{item.title}</span>
                        <span className="text-[10px] text-slate-500 block">{item.note}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>

              {/* ----------------- QUANTIFICATION & VERIFICATION LOOP (FEEDS ③) ----------------- */}
              <div className="mt-3 p-3 rounded-xl bg-gradient-to-r from-purple-50 via-pink-50 to-purple-50 border border-pink-200 relative">
                <div className="flex items-center justify-between pb-1.5 border-b border-pink-200 mb-2">
                  <div className="flex items-center space-x-1.5 text-pink-600 font-bold text-[11px]">
                    <RefreshCw className="w-3.5 h-3.5 text-pink-500 animate-spin" style={{ animationDuration: '8s' }} />
                    <span>Quantification &amp; Verification</span>
                  </div>
                  <span className="text-[9px] font-extrabold uppercase tracking-wider text-pink-700 bg-pink-100 px-1.5 py-0.5 rounded">
                    ⟳ Feeds ③
                  </span>
                </div>

                <div className="text-[11px] font-semibold text-pink-600 italic mb-2">
                  &ldquo;Where risk becomes ₹ and gets proven&rdquo;
                </div>

                <div className="grid grid-cols-2 gap-1.5 text-[10px] text-slate-600">
                  <div className="bg-white px-2 py-1 rounded border border-slate-200">
                    <span className="font-bold text-pink-600">PyFair</span>
                    <span className="text-slate-500 block text-[9px]">Monte Carlo Loss</span>
                  </div>
                  <div className="bg-white px-2 py-1 rounded border border-slate-200">
                    <span className="font-bold text-pink-600">EPSS + DBIR</span>
                    <span className="text-slate-500 block text-[9px]">IBM/Verizon priors</span>
                  </div>
                  <div className="bg-white px-2 py-1 rounded border border-slate-200">
                    <span className="font-bold text-pink-600">OPA (Rego)</span>
                    <span className="text-slate-500 block text-[9px]">Policy evaluation</span>
                  </div>
                  <div className="bg-white px-2 py-1 rounded border border-slate-200">
                    <span className="font-bold text-pink-600">Dagger.io + Trivy</span>
                    <span className="text-slate-500 block text-[9px]">Reproducible gates</span>
                  </div>
                </div>

                <div className="mt-2 text-[9px] text-center text-pink-600 font-semibold flex items-center justify-center space-x-1">
                  <span>↕ Continuous Closed-Loop Feedback into Agent Mesh</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] text-purple-600 font-bold">
              <span>Exports Insights</span>
              <div className="flex items-center space-x-1">
                <span>3 &rarr; 4</span>
                <ArrowRight className="w-3.5 h-3.5 text-purple-500 animate-pulse" />
              </div>
            </div>
          </div>

          {/* ----------------- BOX 4: DELIVERY LAYER ----------------- */}
          <div className="relative flex flex-col justify-between rounded-2xl bg-white border-2 border-emerald-200 p-5 shadow-sm hover:border-emerald-400 transition-all group">
            <div className="flex items-center justify-between mb-3">
              <span className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-700 border border-emerald-200 flex items-center justify-center font-black text-sm">
                ④
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                Actionable Output
              </span>
            </div>

            <div className="space-y-3 flex-1">
              <div>
                <h3 className="font-extrabold text-base text-slate-900 group-hover:text-emerald-600 transition-colors">
                  Delivery Layer
                </h3>
                <div className="text-xs font-semibold text-emerald-600 mt-0.5 italic">
                  &ldquo;What the user actually sees&rdquo;
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200">
                <ul className="space-y-2 text-xs text-slate-600">
                  {[
                    { title: 'Grafana', note: 'Real-time financial exposure & SLA metrics' },
                    { title: 'Metabase', note: 'Self-service executive risk reporting' },
                    { title: 'Backstage Portal', note: 'Unified developer catalog & remediation' },
                    { title: 'Slack / Email', note: 'Targeted alerts with one-click fix PRs' },
                    { title: 'Evidence Pack', note: 'OpenTimestamps & Cosign cryptographic proof' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-emerald-500 font-bold mt-0.5 text-xs">&bull;</span>
                      <div>
                        <span className="font-medium text-slate-800">{item.title}</span>
                        <span className="text-[10px] text-slate-500 block">{item.note}</span>
                      </div>
                    </li>
                  ))}
                </ul>

                {/* Audit proof badge */}
                <div className="mt-4 p-2.5 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center space-x-2 text-[10px] text-emerald-700">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                  <span>Auditor-Ready: SHA-256 OTS digest signed with Cosign keyless PKI</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] text-emerald-600 font-bold">
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
          <div className="w-full border-t-2 border-dashed border-slate-300" />
        </div>
        <div className="relative px-4 py-1.5 rounded-full bg-white border border-slate-200 text-[11px] font-bold text-slate-600 flex items-center space-x-2 shadow-sm">
          <span className="text-cyan-500">▲</span>
          <span className="uppercase tracking-widest text-[10px] text-slate-500">
            Tier 2 Foundation Band (Supports &amp; Secures Every Step in Tier 1)
          </span>
          <span className="text-cyan-500">▲</span>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TIER 2: SUPPORTING / CROSS-CUTTING FOUNDATION (Smaller, distinct band)    */}
      {/* ========================================================================= */}
      <div className="p-6 rounded-2xl bg-gradient-to-b from-white to-slate-50 border border-slate-200 shadow-sm space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 pb-3">
          <div>
            <div className="text-xs font-extrabold tracking-wider uppercase text-cyan-600 flex items-center space-x-2">
              <Boxes className="w-4 h-4" />
              <span>Tier 2 — Supporting &amp; Cross-Cutting Foundation</span>
            </div>
            <p className="text-[11px] text-slate-500 mt-0.5">
              These shared capabilities do not come &ldquo;after&rdquo; Tier 1 — they run continuously underneath and secure all primary stages.
            </p>
          </div>
          <span className="px-2.5 py-1 rounded text-[10px] font-mono bg-cyan-50 text-cyan-700 border border-cyan-200 shrink-0">
            Unnumbered Support Band
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* ----------------- SUPPORT BOX A: CYBERSECURITY TOOLS ----------------- */}
          <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 hover:border-cyan-300 transition-all space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-500" />
                  <h4 className="font-extrabold text-sm text-slate-900">
                    Cybersecurity Tools — Open Source
                  </h4>
                </div>
                <div className="text-xs font-medium text-cyan-600 italic mt-0.5">
                  &ldquo;What secures the pipeline itself&rdquo;
                </div>
              </div>
              <span className="text-[10px] font-semibold text-slate-500 bg-white px-2 py-0.5 rounded border border-slate-200">
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
                  className="p-2 rounded-lg bg-white border border-slate-200 hover:border-slate-300 flex flex-col justify-between"
                >
                  <span className="font-bold text-slate-800 text-xs">{tool.name}</span>
                  <span className="text-[10px] text-slate-400 font-mono mt-0.5">{tool.category}</span>
                </div>
              ))}
            </div>
          </div>

          {/* ----------------- SUPPORT BOX B: CROSS-CUTTING PLATFORM SERVICES ----------------- */}
          <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 hover:border-cyan-300 transition-all space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-cyan-500" />
                  <h4 className="font-extrabold text-sm text-slate-900">
                    Cross-Cutting Platform Services
                  </h4>
                </div>
                <div className="text-xs font-medium text-cyan-600 italic mt-0.5">
                  &ldquo;What runs underneath everything&rdquo;
                </div>
              </div>
              <span className="text-[10px] font-semibold text-slate-500 bg-white px-2 py-0.5 rounded border border-slate-200">
                Core Infra
              </span>
            </div>

            {/* 4 Pillars of Foundation Services */}
            <div className="space-y-2.5 text-xs">
              <div className="p-3 rounded-lg bg-white border border-slate-200 flex items-start space-x-3">
                <Lock className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="font-bold text-slate-800">Identity &amp; Access</div>
                  <div className="text-slate-500 text-[11px]">
                    <strong className="text-amber-600">Keycloak</strong> — OpenID Connect (OIDC) SSO, RBAC roles (CISO, SecOps, Developer)
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-white border border-slate-200 flex items-start space-x-3">
                <Workflow className="w-4 h-4 text-cyan-500 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="font-bold text-slate-800">Workflow Orchestration</div>
                  <div className="text-slate-500 text-[11px]">
                    <strong className="text-cyan-600">Temporal.io</strong> — Distributed state machines, resilient scan execution, retry isolation
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-white border border-slate-200 flex items-start space-x-3">
                <Server className="w-4 h-4 text-blue-500 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="font-bold text-slate-800">Infrastructure</div>
                  <div className="text-slate-500 text-[11px]">
                    <strong className="text-blue-600">Docker, Kubernetes &amp; Helm</strong> — Containerized microservices, high-availability deployments
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-white border border-slate-200 flex items-start space-x-3">
                <FileCheck className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="font-bold text-slate-800 flex items-center justify-between">
                    <span>CI/CD Security</span>
                    <span className="text-[9px] font-mono bg-emerald-100 text-emerald-700 px-1.5 py-0.2 rounded border border-emerald-200">
                      Workflow Verified
                    </span>
                  </div>
                  <div className="text-slate-500 text-[11px]">
                    <strong className="text-emerald-600">GitHub Actions</strong> + Trivy / Gitleaks / Semgrep / Checkov automated pre-merge gates
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
        <div className="rounded-2xl bg-slate-50 border border-slate-200 p-5 space-y-4 animate-fade-in">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <div>
              <h4 className="text-sm font-bold text-slate-800 flex items-center space-x-2">
                <Radio className="w-4 h-4 text-emerald-500 animate-pulse" />
                <span>Active Scanner Microservices &amp; Platform Ports</span>
              </h4>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Each scanner operates as an isolated FastAPI microservice with Kafka publisher and health probe endpoints.
              </p>
            </div>
            <span className="text-[10px] font-mono text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded border border-emerald-200">
              10 Services Online
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
            {TOPOLOGY_SERVICES.map((s, i) => (
              <div
                key={i}
                className="p-3 rounded-xl bg-white border border-slate-200 flex flex-col justify-between space-y-2 hover:border-slate-300 transition-all"
              >
                <div>
                  <div className="font-bold text-xs text-slate-900 truncate">{s.name}</div>
                  <div className="text-[10px] text-slate-400 truncate">{s.type}</div>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-200 text-[10px]">
                  <span className="font-mono text-blue-600">:{s.port}</span>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-100 text-emerald-700 border border-emerald-200">
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
