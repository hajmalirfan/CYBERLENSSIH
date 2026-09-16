import React from 'react';
import { Search, CheckCircle2, AlertCircle, ArrowUpDown } from 'lucide-react';

export default function RiskQueue({
  riskQueue,
  selectedFinding,
  setSelectedFinding,
  selectedToolFilter,
  setSelectedToolFilter,
  searchQuery,
  setSearchQuery,
  onToggleVerification
}) {
  const tools = ['all', 'semgrep', 'checkov', 'cosign', 'falco', 'suricata', 'zap'];

  return (
    <div className="space-y-4">
      {/* Controls & Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 glass-card rounded-2xl p-4">
        {/* Tool Filter Tabs */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider mr-1">
            Filter:
          </span>
          {tools.map((t) => (
            <button
              key={t}
              onClick={() => setSelectedToolFilter(t)}
              className={`px-3 py-1 rounded-xl text-xs font-semibold uppercase tracking-wider transition-all ${
                selectedToolFilter === t
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-500/25'
                  : 'bg-slate-900/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Search input */}
        <div className="relative">
          <input
            type="text"
            placeholder="Search finding, rule, or asset..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-slate-900/90 border border-slate-700/80 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-64 shadow-inner"
          />
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2 pointer-events-none" />
        </div>
      </div>

      {/* Findings Table */}
      <div className="glass-card rounded-2xl overflow-hidden border border-slate-800">
        <div className="px-6 py-4 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-2 bg-slate-900/50">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <span>Open Findings Ranked by Financial Loss Exposure</span>
              <span className="text-xs font-mono text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded-full border border-blue-500/20">
                PyFair Quantitative Model
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Replaces subjective Low/Medium/High labels with quantified INR loss exposure (LEF &times; Loss Magnitude)
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono bg-slate-800/80 px-2.5 py-1 rounded-lg">
            {riskQueue.length} findings
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-bold tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-5 py-3.5">
                  <div className="flex items-center space-x-1">
                    <span>Risk Exposure (₹)</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-500" />
                  </div>
                </th>
                <th className="px-5 py-3.5">Finding Title & Rule</th>
                <th className="px-5 py-3.5">Target Asset</th>
                <th className="px-5 py-3.5">Scanner</th>
                <th className="px-5 py-3.5">Category</th>
                <th className="px-5 py-3.5 text-center">SecOps Status</th>
                <th className="px-5 py-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {riskQueue.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-5 py-12 text-center text-slate-500">
                    No findings match the selected filter.
                  </td>
                </tr>
              ) : (
                riskQueue.map((f) => {
                  const isSelected = selectedFinding && selectedFinding.finding_id === f.finding_id;
                  return (
                    <tr
                      key={f.finding_id}
                      onClick={() => setSelectedFinding(f)}
                      className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                        isSelected ? 'bg-blue-900/20 border-l-4 border-l-blue-500' : ''
                      }`}
                    >
                      {/* Risk Exposure */}
                      <td className="px-5 py-4 font-mono font-bold text-red-400 text-sm whitespace-nowrap">
                        {f.formatted_exposure_inr}
                      </td>

                      {/* Title & Rule */}
                      <td className="px-5 py-4 max-w-xs">
                        <div className="font-semibold text-slate-100 truncate">{f.title}</div>
                        <div className="text-[11px] font-mono text-slate-500 truncate mt-0.5">{f.rule_id}</div>
                      </td>

                      {/* Target Asset */}
                      <td className="px-5 py-4 font-mono text-slate-400 text-[11px] truncate max-w-[180px]">
                        {f.asset_id}
                      </td>

                      {/* Tool Badge */}
                      <td className="px-5 py-4">
                        <span className="px-2.5 py-1 rounded-lg uppercase font-mono text-[10px] font-bold bg-slate-800 text-blue-400 border border-slate-700">
                          {f.tool}
                        </span>
                      </td>

                      {/* Category */}
                      <td className="px-5 py-4 capitalize text-slate-400">
                        {f.category}
                      </td>

                      {/* Verified Status */}
                      <td className="px-5 py-4 text-center whitespace-nowrap">
                        {f.verified ? (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>Verified</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                            <AlertCircle className="w-3 h-3" />
                            <span>Pending</span>
                          </span>
                        )}
                      </td>

                      {/* Action */}
                      <td className="px-5 py-4 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onToggleVerification(f.finding_id);
                          }}
                          className={`px-3 py-1 text-xs rounded-xl font-semibold border transition-all ${
                            f.verified
                              ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                              : 'bg-blue-600 border-blue-500 text-white hover:bg-blue-500 shadow-sm'
                          }`}
                        >
                          {f.verified ? 'Unverify' : 'Verify'}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
