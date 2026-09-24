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
          <span className="text-xs font-bold text-slate-500 uppercase tracking-wider mr-1">
            Filter:
          </span>
          {tools.map((t) => (
            <button
              key={t}
              onClick={() => setSelectedToolFilter(t)}
              className={`px-3 py-1 rounded-xl text-xs font-semibold uppercase tracking-wider transition-all ${
                selectedToolFilter === t
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-500/25'
                  : 'bg-slate-100 text-slate-500 hover:text-slate-900 hover:bg-slate-200'
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
            className="bg-slate-50 border border-slate-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-500 w-64"
          />
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2 pointer-events-none" />
        </div>
      </div>

      {/* Findings Table */}
      <div className="glass-card rounded-2xl overflow-hidden border border-slate-200">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2 bg-slate-50">
          <div>
            <h2 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
              <span>Open Findings Ranked by Financial Loss Exposure</span>
              <span className="text-xs font-mono text-blue-600 bg-blue-50 px-2 py-0.5 rounded-full border border-blue-200">
                PyFair Quantitative Model
              </span>
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Replaces subjective Low/Medium/High labels with quantified INR loss exposure (LEF &times; Loss Magnitude)
            </p>
          </div>
          <span className="text-xs text-slate-500 font-mono bg-slate-100 px-2.5 py-1 rounded-lg">
            {riskQueue.length} findings
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-500 uppercase text-[10px] font-bold tracking-wider border-b border-slate-200">
              <tr>
                <th className="px-5 py-3.5">
                  <div className="flex items-center space-x-1">
                    <span>Risk Exposure (₹)</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-400" />
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
            <tbody className="divide-y divide-slate-200">
              {riskQueue.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-5 py-12 text-center text-slate-400">
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
                      className={`hover:bg-slate-50 cursor-pointer transition-colors ${
                        isSelected ? 'bg-blue-50 border-l-4 border-l-blue-500' : ''
                      }`}
                    >
                      {/* Risk Exposure */}
                      <td className="px-5 py-4 font-mono font-bold text-red-600 text-sm whitespace-nowrap">
                        {f.formatted_exposure_inr}
                      </td>

                      {/* Title & Rule */}
                      <td className="px-5 py-4 max-w-xs">
                        <div className="font-semibold text-slate-900 truncate">{f.title}</div>
                        <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">{f.rule_id}</div>
                      </td>

                      {/* Target Asset */}
                      <td className="px-5 py-4 font-mono text-slate-500 text-[11px] truncate max-w-[180px]">
                        {f.asset_id}
                      </td>

                      {/* Tool Badge */}
                      <td className="px-5 py-4">
                        <span className="px-2.5 py-1 rounded-lg uppercase font-mono text-[10px] font-bold bg-slate-100 text-blue-700 border border-slate-200">
                          {f.tool}
                        </span>
                      </td>

                      {/* Category */}
                      <td className="px-5 py-4 capitalize text-slate-500">
                        {f.category}
                      </td>

                      {/* Verified Status */}
                      <td className="px-5 py-4 text-center whitespace-nowrap">
                        {f.verified ? (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>Verified</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-200">
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
                              ? 'bg-slate-100 border-slate-200 text-slate-600 hover:bg-slate-200'
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
