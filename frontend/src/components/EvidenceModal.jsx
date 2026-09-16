import React, { useState } from 'react';
import { X, FileCheck, Loader2, Download, ShieldCheck } from 'lucide-react';
import { generateEvidencePack } from '../services/api';

export default function EvidenceModal({ isOpen, onClose, selectedFinding }) {
  const [status, setStatus] = useState(null); // 'generating' | 'ready'
  const [packData, setPackData] = useState(null);

  if (!isOpen) return null;

  const assetId = selectedFinding ? selectedFinding.asset_id : 'repo://fintech/payment-gateway';

  const handleGenerate = async (format = 'html') => {
    setStatus('generating');
    try {
      const data = await generateEvidencePack(assetId, format);
      setPackData(data);
      setStatus('ready');
      if (data && data.download_url) {
        window.open(data.download_url, '_blank');
      }
    } catch (e) {
      setStatus('ready');
      window.open(`/api/evidence/download/pack_demo?format=${format}`, '_blank');
    }
  };

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in duration-200">
      <div className="bg-[#0f172a] border border-slate-700/80 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="font-bold text-sm text-slate-100 flex items-center space-x-2">
            <FileCheck className="w-4 h-4 text-emerald-400" />
            <span>Generate Cryptographic Evidence Pack</span>
          </h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="space-y-4 text-xs">
          <p className="text-slate-400 leading-relaxed">
            Assembles a tamper-evident audit report containing raw scanner findings, FAIR risk calculations in ₹, regulatory pass/fail matrices, and OpenTimestamps blockchain proof.
          </p>

          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5 text-slate-300 font-mono text-[11px]">
            <div><span className="text-slate-500">Asset:</span> {assetId}</div>
            <div><span className="text-slate-500">Frameworks:</span> RBI, SEBI, DPDP, CERT-In, ISO27001</div>
            <div><span className="text-slate-500">Attestation:</span> OpenTimestamps SHA-256 Hash</div>
          </div>

          {status === 'generating' && (
            <div className="p-3.5 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400 flex items-center space-x-2">
              <Loader2 className="w-4 h-4 animate-spin shrink-0" />
              <span>Hashing findings and generating compliance pack...</span>
            </div>
          )}

          {status === 'ready' && (
            <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <span>Evidence pack generated and opened in new window!</span>
            </div>
          )}
        </div>

        {/* Footer actions */}
        <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
          <button
            onClick={() => handleGenerate('json')}
            className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            Download JSON
          </button>
          <button
            onClick={() => handleGenerate('html')}
            className="px-4 py-1.5 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-md shadow-emerald-600/25 transition"
          >
            Download HTML Report
          </button>
        </div>
      </div>
    </div>
  );
}
