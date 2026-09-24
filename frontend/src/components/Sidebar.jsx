import React from 'react';
import logoImg from '../assets/cyberlens-logo.png';
import {
  IndianRupee,
  Layers,
  Scale,
  LineChart,
  Cpu,
  Network,
  UserCheck,
  LogOut,
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, riskCount, role, user, onLogout }) {
  const navItems = [
    { id: 'risk-queue', label: 'Risk Queue (₹)', icon: IndianRupee, badge: riskCount, badgeColor: 'bg-red-100 text-red-600' },
    { id: 'asset-detail', label: 'Asset Trace & FAIR', icon: Layers },
    { id: 'compliance', label: 'Compliance (OPA)', icon: Scale },
    { id: 'attack-graph', label: 'Attack Graph (AGE)', icon: Network },
    { id: 'dashboards', label: 'Grafana Telemetry', icon: LineChart },
    { id: 'topology', label: 'Architecture & Pipeline', icon: Cpu },
  ];

  const initials = user?.name
    ? user.name.split(' ').map((p) => p[0]).join('').slice(0, 2).toUpperCase()
    : (role || 'US').substring(0, 2).toUpperCase();

  return (
    <aside className="w-64 border-r border-slate-200 bg-white flex flex-col justify-between shrink-0 select-none">
      <div>
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-200 flex items-center space-x-3">
          <img src={logoImg} alt="CYBERLENS logo" className="w-10 h-10 rounded-xl object-cover shadow-md shrink-0" />
          <div>
            <div className="font-extrabold text-lg tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-slate-900 via-slate-700 to-blue-600">
              CYBERLENS
            </div>
            <div className="text-[10px] font-bold tracking-wider text-blue-600 uppercase">
              SIH 2026 · Developed by SecuriX Team
            </div>
          </div>
        </div>

        {/* Navigation items */}
        <nav className="p-3 space-y-1">
          <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-500">
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
                    ? 'bg-blue-50 text-blue-700 border border-blue-200 shadow-sm'
                    : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span className="truncate">{item.label}</span>
                {item.badge !== undefined && (
                  <span className={`ml-auto text-[10px] px-2 py-0.5 rounded-full font-bold ${item.badgeColor || 'bg-slate-100 text-slate-500'}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Logged-in DB user card (replaces static persona) */}
      <div className="p-4 border-t border-slate-200 bg-slate-50">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 flex items-center justify-center font-bold text-xs text-white shadow-md">
            {initials}
          </div>
          <div className="text-xs truncate flex-1">
            <div className="font-semibold text-slate-800 truncate flex items-center space-x-1">
              <span className="truncate">{user?.name || `${role} User`}</span>
              <UserCheck className="w-3 h-3 text-emerald-500 inline shrink-0" />
            </div>
            <div className="text-slate-500 text-[10px] font-mono truncate">{user?.email || 'Postgres auth'}</div>
            <div className="text-blue-600 text-[10px] font-semibold capitalize">{role}</div>
          </div>
          {onLogout && (
            <button
              onClick={onLogout}
              title="Logout"
              className="p-1.5 rounded-lg text-slate-400 hover:text-red-500 hover:bg-red-50 transition-all"
            >
              <LogOut className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </aside>
  );
}
