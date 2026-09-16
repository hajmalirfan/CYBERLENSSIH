import React from 'react';
import { 
  ShieldAlert, 
  IndianRupee, 
  Layers, 
  Scale, 
  LineChart, 
  Cpu, 
  Network, 
  UserCheck 
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, riskCount, role }) {
  const navItems = [
    { id: 'risk-queue', label: 'Risk Queue (₹)', icon: IndianRupee, badge: riskCount, badgeColor: 'bg-red-500/20 text-red-400' },
    { id: 'asset-detail', label: 'Asset Trace & FAIR', icon: Layers },
    { id: 'compliance', label: 'Compliance (OPA)', icon: Scale },
    { id: 'attack-graph', label: 'Attack Graph (AGE)', icon: Network },
    { id: 'dashboards', label: 'Grafana Telemetry', icon: LineChart },
    { id: 'topology', label: 'Architecture & Pipeline', icon: Cpu },
  ];

  return (
    <aside className="w-64 border-r border-slate-800/80 bg-[#0c1220] flex flex-col justify-between shrink-0 select-none">
      <div>
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-800/80 flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/25">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="font-extrabold text-lg tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-blue-400">
              SecuriX
            </div>
            <div className="text-[10px] font-bold tracking-wider text-blue-400 uppercase">
              SIH 2026 Developer Portal
            </div>
          </div>
        </div>

        {/* Navigation items */}
        <nav className="p-3 space-y-1">
          <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
            Backstage Plugins
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span className="truncate">{item.label}</span>
                {item.badge !== undefined && (
                  <span className={`ml-auto text-[10px] px-2 py-0.5 rounded-full font-bold ${item.badgeColor || 'bg-slate-800 text-slate-300'}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Keycloak SSO & User Card */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-900/40">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 flex items-center justify-center font-bold text-xs text-white shadow-md">
            {role.substring(0, 2).toUpperCase()}
          </div>
          <div className="text-xs truncate">
            <div className="font-semibold text-slate-200 capitalize flex items-center space-x-1">
              <span>{role} Persona</span>
              <UserCheck className="w-3 h-3 text-emerald-400 inline" />
            </div>
            <div className="text-slate-500 text-[10px] font-mono">Keycloak SSO: securix</div>
          </div>
        </div>
      </div>
    </aside>
  );
}
