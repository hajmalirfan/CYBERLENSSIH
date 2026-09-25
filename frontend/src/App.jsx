import React, { useState, useEffect, useMemo } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import KPICards from './components/KPICards';
import RiskQueue from './components/RiskQueue';
import AssetDetail from './components/AssetDetail';
import CompliancePlugin from './components/CompliancePlugin';
import AttackGraph from './components/AttackGraph';
import GrafanaEmbeds from './components/GrafanaEmbeds';
import TopologyView from './components/TopologyView';
import ScanModal from './components/ScanModal';
import EvidenceModal from './components/EvidenceModal';
import AuthPage from './components/AuthPage';
import { fetchRiskQueue, toggleVerifyFinding, fetchCurrentUser, getStoredUser, clearSession } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('risk-queue');
  const [user, setUser] = useState(() => getStoredUser());
  const [authChecked, setAuthChecked] = useState(false);
  // Role always comes from the logged-in DB user — no static default persona.
  const [riskQueue, setRiskQueue] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [selectedToolFilter, setSelectedToolFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isEvidenceModalOpen, setIsEvidenceModalOpen] = useState(false);

  const role = user?.role || 'analyst';

  // Validate stored JWT against Postgres on mount
  useEffect(() => {
    async function checkAuth() {
      const me = await fetchCurrentUser();
      if (me) setUser(me);
      else setUser(null);
      setAuthChecked(true);
    }
    checkAuth();
  }, []);

  // Fetch live risk queue only after login
  useEffect(() => {
    if (!user) return;
    async function loadData() {
      const data = await fetchRiskQueue();
      if (Array.isArray(data) && data.length > 0) {
        setRiskQueue(data);
        setSelectedFinding(data[0]);
      }
    }
    loadData();
  }, [user]);

  const handleAuthSuccess = (loggedUser) => {
    setUser(loggedUser);
  };

  const handleLogout = () => {
    clearSession();
    setUser(null);
  };

  // Compute total financial exposure in INR
  const totalExposureINR = useMemo(() => {
    return riskQueue.reduce((acc, f) => acc + (f.expected_annual_loss_inr || 0), 0);
  }, [riskQueue]);

  // Verified findings count
  const verifiedCount = useMemo(() => {
    return riskQueue.filter((f) => f.verified).length;
  }, [riskQueue]);

  // Filtered queue based on tool and search term
  const filteredQueue = useMemo(() => {
    return riskQueue.filter((f) => {
      const matchTool = selectedToolFilter === 'all' || f.tool === selectedToolFilter;
      const matchSearch =
        f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (f.asset_id && f.asset_id.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (f.rule_id && f.rule_id.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchTool && matchSearch;
    });
  }, [riskQueue, selectedToolFilter, searchQuery]);

  // Verification toggle with local update + backend async sync
  const handleToggleVerification = async (findingId) => {
    setRiskQueue((prev) =>
      prev.map((f) => {
        if (f.finding_id === findingId) {
          return { ...f, verified: !f.verified };
        }
        return f;
      })
    );

    if (selectedFinding && selectedFinding.finding_id === findingId) {
      setSelectedFinding((prev) => ({ ...prev, verified: !prev.verified }));
    }

    await toggleVerifyFinding(findingId, user?.name || 'SecOps Analyst');
  };

  const handleScanComplete = (res) => {
    // Optionally refresh queue if new findings were produced
  };

  if (!authChecked) {
    return (
      <div className="flex h-screen items-center justify-center bg-white text-slate-500 text-sm">
        Checking session...
      </div>
    );
  }

  if (!user) {
    return <AuthPage onAuthSuccess={handleAuthSuccess} />;
  }

  return (
    <div className="flex h-screen bg-white text-slate-900 font-sans overflow-hidden">
      {/* 1. Left Backstage Portal Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        riskCount={riskQueue.length}
        role={role}
        user={user}
        onLogout={handleLogout}
      />

      {/* 2. Main Application Workspace */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <Header
          role={role}
          user={user}
          onLogout={handleLogout}
          onOpenScan={() => setIsScanModalOpen(true)}
          onOpenEvidence={() => setIsEvidenceModalOpen(true)}
        />

        {/* Scrollable Content Area */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6 bg-slate-50">
          {/* Top KPI Metrics Banner */}
          <KPICards
            totalExposureINR={totalExposureINR}
            riskCount={riskQueue.length}
            verifiedCount={verifiedCount}
            complianceScore={84.6}
          />

          {/* Plugin Screen 1: Risk Queue (₹ Financial Ranking) */}
          {activeTab === 'risk-queue' && (
            <div className="space-y-6">
              <RiskQueue
                riskQueue={filteredQueue}
                selectedFinding={selectedFinding}
                setSelectedFinding={setSelectedFinding}
                selectedToolFilter={selectedToolFilter}
                setSelectedToolFilter={setSelectedToolFilter}
                searchQuery={searchQuery}
                setSearchQuery={setSearchQuery}
                onToggleVerification={handleToggleVerification}
              />

              {/* Bottom preview of selected finding */}
              {selectedFinding && (
                <AssetDetail
                  finding={selectedFinding}
                  onToggleVerification={handleToggleVerification}
                  onGenerateEvidence={() => setIsEvidenceModalOpen(true)}
                />
              )}
            </div>
          )}

          {/* Plugin Screen 2: Dedicated Asset Trace & FAIR Detail */}
          {activeTab === 'asset-detail' && (
            <div className="space-y-6">
              <AssetDetail
                finding={selectedFinding}
                onToggleVerification={handleToggleVerification}
                onGenerateEvidence={() => setIsEvidenceModalOpen(true)}
              />
            </div>
          )}

          {/* Plugin Screen 3: Regulatory Compliance (OPA) */}
          {activeTab === 'compliance' && <CompliancePlugin />}

          {/* Plugin Screen 4: Apache AGE Attack Graph */}
          {activeTab === 'attack-graph' && <AttackGraph findings={riskQueue} />}

          {/* Plugin Screen 5: Grafana Telemetry Embeds */}
          {activeTab === 'dashboards' && <GrafanaEmbeds />}

          {/* Plugin Screen 6: 6 Scanners & Topology Health */}
          {activeTab === 'topology' && <TopologyView />}
        </main>
      </div>

      {/* Interactive Scan Modal */}
      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onScanComplete={handleScanComplete}
      />

      {/* Evidence Pack Generation Modal */}
      <EvidenceModal
        isOpen={isEvidenceModalOpen}
        onClose={() => setIsEvidenceModalOpen(false)}
        selectedFinding={selectedFinding}
      />
    </div>
  );
}
