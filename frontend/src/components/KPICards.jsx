import React from 'react';
import { IndianRupee, ShieldCheck, CheckCircle2, TrendingUp, AlertTriangle } from 'lucide-react';

export default function KPICards({ totalExposureINR, riskCount, verifiedCount, complianceScore = 84.6 }) {
  const exposureInLakhs = (totalExposureINR / 100000).toFixed(1);
  const exposureInCrores = (totalExposureINR / 10000000).toFixed(2);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* 1. Total Financial Exposure */}
      <div className="glass-card glass-card-hover rounded-2xl p-5 border-l-4 border-l-red-500 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between text-xs font-bold text-slate-500 uppercase tracking-wider">
            <span>Total Risk Exposure</span>
            <IndianRupee className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-2xl font-black text-red-600 mt-2 font-mono tracking-tight">
            ₹{exposureInLakhs} Lakhs
          </div>
        </div>
        <div className="text-xs text-slate-500 mt-2 flex items-center space-x-1.5">
          <span className="text-emerald-600 font-semibold flex items-center">
            <TrendingUp className="w-3 h-3 mr-1 inline" />
            PyFair Quantified
          </span>
          <span className="text-slate-300">&bull;</span>
          <span>(₹{exposureInCrores} Cr)</span>
        </div>
      </div>

      {/* 2. Active Security Findings */}
      <div className="glass-card glass-card-hover rounded-2xl p-5 border-l-4 border-l-amber-500 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between text-xs font-bold text-slate-500 uppercase tracking-wider">
            <span>Active Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-black text-slate-900 mt-2">
            {riskCount} <span className="text-xs font-medium text-slate-500">across 6 tools</span>
          </div>
        </div>
        <div className="text-xs text-slate-500 mt-2">
          <span className="text-emerald-600 font-semibold">{verifiedCount} verified</span> by SecOps team
        </div>
      </div>

      {/* 3. Compliance Health Score */}
      <div className="glass-card glass-card-hover rounded-2xl p-5 border-l-4 border-l-blue-500 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between text-xs font-bold text-slate-500 uppercase tracking-wider">
            <span>Compliance Health</span>
            <ShieldCheck className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-black text-blue-600 mt-2">
            {complianceScore}%
          </div>
        </div>
        <div className="text-xs text-slate-500 mt-2 truncate">
          RBI &bull; SEBI &bull; DPDP &bull; CERT-In &bull; ISO
        </div>
      </div>

      {/* 4. Cryptographic Proof Status */}
      <div className="glass-card glass-card-hover rounded-2xl p-5 border-l-4 border-l-emerald-500 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between text-xs font-bold text-slate-500 uppercase tracking-wider">
            <span>Evidence Attestation</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-black text-emerald-600 mt-2 flex items-center space-x-2">
            <span>Anchored</span>
          </div>
        </div>
        <div className="text-xs text-slate-500 mt-2 font-mono truncate">
          OpenTimestamps &bull; SHA-256
        </div>
      </div>
    </div>
  );
}
