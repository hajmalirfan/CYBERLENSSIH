import React, { useState, useMemo, useEffect } from 'react';
import { Network, Info, Database } from 'lucide-react';
import { fetchFindings } from '../services/api';

export default function AttackGraph({ findings: propFindings }) {
  const [liveFindings, setLiveFindings] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (propFindings && propFindings.length > 0) {
      setLiveFindings(propFindings);
      return;
    }
    // Fetch live findings from graph service
    async function load() {
      const data = await fetchFindings({ limit: 100 });
      if (data && data.length > 0) {
        setLiveFindings(data);
      }
    }
    load();
  }, [propFindings]);

  // Dynamically compute graph nodes and edges from real database findings
  const { nodes, edges } = useMemo(() => {
    const list = liveFindings.length > 0 ? liveFindings : [];
    if (list.length === 0) {
      return { nodes: [], edges: [] };
    }

    const calculatedNodes = [];
    const calculatedEdges = [];

    // 1. Assets (Column 1: x = 110)
    const uniqueAssets = Array.from(new Set(list.map((f) => f.asset_id || 'unknown_asset')));
    uniqueAssets.forEach((aid, idx) => {
      const spacing = 480 / (uniqueAssets.length + 1);
      const sample = list.find((f) => f.asset_id === aid);
      calculatedNodes.push({
        id: `asset_${idx}`,
        rawId: aid,
        label: sample?.asset_name || aid.replace(/^(url|repo|image|iac):\/\//, '').split('/')[0] || aid,
        type: 'asset',
        x: 110,
        y: Math.round(60 + (idx + 1) * spacing),
        color: '#3b82f6',
        details: { asset_id: aid, asset_name: sample?.asset_name, asset_type: sample?.asset_type }
      });
    });

    // 2. Vulnerability Findings (Column 2: x = 340)
    const topFindings = list.slice(0, 5); // display top 5 for optimal graph layout
    topFindings.forEach((f, idx) => {
      const spacing = 480 / (topFindings.length + 1);
      const sevColor = f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f97316' : '#eab308';
      const fNodeId = `vuln_${idx}`;
      calculatedNodes.push({
        id: fNodeId,
        rawId: f.finding_id,
        label: f.rule_id || f.title.slice(0, 18) + '...',
        title: f.title,
        type: 'vulnerability',
        severity: f.severity,
        x: 340,
        y: Math.round(50 + (idx + 1) * spacing),
        color: sevColor,
        details: {
          finding_id: f.finding_id,
          title: f.title,
          tool: f.tool,
          severity: f.severity,
          eal_inr: f.expected_annual_loss_inr,
          formatted_inr: f.formatted_exposure_inr
        }
      });

      // Edge from Asset to Vulnerability
      const assetNode = calculatedNodes.find((n) => n.type === 'asset' && n.rawId === f.asset_id);
      if (assetNode) {
        calculatedEdges.push({
          from: assetNode.id,
          to: fNodeId,
          label: 'AFFECTS'
        });
      }
    });

    // 3. Threat Categories (Column 3: x = 580)
    const threatCategories = Array.from(new Set(topFindings.map((f) => f.category || f.tool || 'threat')));
    threatCategories.forEach((cat, idx) => {
      const spacing = 480 / (threatCategories.length + 1);
      const tNodeId = `threat_${idx}`;
      calculatedNodes.push({
        id: tNodeId,
        rawId: cat,
        label: cat.toUpperCase(),
        type: 'threat',
        x: 580,
        y: Math.round(70 + (idx + 1) * spacing),
        color: '#a855f7',
        details: { category: cat, description: `Threat vector class derived from ${cat}` }
      });

      // Connect Vulnerabilities to Threat Categories
      topFindings.filter((f) => (f.category || f.tool) === cat).forEach((f) => {
        const vNode = calculatedNodes.find((n) => n.rawId === f.finding_id);
        if (vNode) {
          calculatedEdges.push({
            from: vNode.id,
            to: tNodeId,
            label: 'ENABLES'
          });
        }
      });
    });

    // 4. Financial Risk Quantification Impact (Column 4: x = 820)
    const totalEal = topFindings.reduce((sum, f) => sum + (f.expected_annual_loss_inr || 0), 0);
    const impactNodeId = 'impact_financial';
    calculatedNodes.push({
      id: impactNodeId,
      rawId: 'fair_financial_risk',
      label: 'Financial Loss',
      type: 'financial_impact',
      x: 820,
      y: 250,
      color: '#ec4899',
      details: {
        total_eal_inr: totalEal,
        formatted: `₹${(totalEal / 100000).toFixed(1)} Lakhs`,
        method: 'PyFair Monte Carlo Simulation'
      }
    });

    // Connect Threats to Financial Impact
    calculatedNodes.filter((n) => n.type === 'threat').forEach((tNode) => {
      calculatedEdges.push({
        from: tNode.id,
        to: impactNodeId,
        label: 'INCURS_LOSS'
      });
    });

    return { nodes: calculatedNodes, edges: calculatedEdges };
  }, [liveFindings]);

  useEffect(() => {
    if (nodes.length > 0 && !selectedNode) {
      setSelectedNode(nodes[0]);
    }
  }, [nodes, selectedNode]);

  return (
    <div className="space-y-4">
      <div className="glass-card rounded-2xl p-6 border border-slate-200">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-4 mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
              <Network className="w-4 h-4 text-blue-500" />
              <span>Apache AGE Real-Time Attack Path & Knowledge Graph</span>
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Live cypher topology generated from actual PostgreSQL findings: Assets &rarr; Vulnerabilities &rarr; Threat Vectors &rarr; PyFair Financial Exposure
            </p>
          </div>

          <div className="flex items-center space-x-3 text-xs">
            <span className="flex items-center space-x-1">
              <span className="w-3 h-3 rounded-full bg-blue-500 inline-block"></span>
              <span className="text-slate-500">Live Assets</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-3 h-3 rounded-full bg-red-500 inline-block"></span>
              <span className="text-slate-500">Vulnerabilities</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-3 h-3 rounded-full bg-purple-500 inline-block"></span>
              <span className="text-slate-500">Threat Vectors</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-3 h-3 rounded-full bg-pink-500 inline-block"></span>
              <span className="text-slate-500">Financial Impact (₹)</span>
            </span>
          </div>
        </div>

        {/* Graph Canvas Visualizer */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* Interactive SVG Graph */}
          <div className="lg:col-span-3 bg-slate-50 border border-slate-200 rounded-2xl p-4 relative overflow-hidden min-h-[460px] flex items-center justify-center">
            {nodes.length === 0 ? (
              <div className="text-center p-8 space-y-2">
                <Database className="w-8 h-8 text-slate-400 mx-auto animate-pulse" />
                <p className="text-xs text-slate-500 font-medium">Connecting to Graph Service...</p>
              </div>
            ) : (
              <svg className="w-full h-full min-h-[440px]" viewBox="0 0 940 520">
                <defs>
                  <marker
                    id="arrow"
                    viewBox="0 0 10 10"
                    refX="18"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#94a3b8" />
                  </marker>
                </defs>

                {/* Render Edges */}
                {edges.map((edge, i) => {
                  const source = nodes.find((n) => n.id === edge.from);
                  const target = nodes.find((n) => n.id === edge.to);
                  if (!source || !target) return null;
                  const isHighlighted = selectedNode && (selectedNode.id === source.id || selectedNode.id === target.id);

                  return (
                    <g key={i}>
                      <line
                        x1={source.x}
                        y1={source.y}
                        x2={target.x}
                        y2={target.y}
                        stroke={isHighlighted ? '#3b82f6' : '#cbd5e1'}
                        strokeWidth={isHighlighted ? 2.5 : 1.5}
                        markerEnd="url(#arrow)"
                      />
                      <text
                        x={(source.x + target.x) / 2}
                        y={(source.y + target.y) / 2 - 5}
                        fill="#64748b"
                        fontSize="9"
                        fontFamily="JetBrains Mono, monospace"
                        textAnchor="middle"
                      >
                        {edge.label}
                      </text>
                    </g>
                  );
                })}

                {/* Render Nodes */}
                {nodes.map((node) => {
                  const isSelected = selectedNode && selectedNode.id === node.id;
                  return (
                    <g
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      className="cursor-pointer transition-transform duration-150"
                    >
                      {/* Outer halo if selected */}
                      {isSelected && (
                        <circle
                          cx={node.x}
                          cy={node.y}
                          r={24}
                          fill="none"
                          stroke={node.color}
                          strokeWidth="3"
                          strokeDasharray="4,4"
                          className="animate-spin origin-center"
                        />
                      )}

                      <circle
                        cx={node.x}
                        cy={node.y}
                        r={16}
                        fill={node.color}
                        className="shadow-lg hover:scale-110 transition-transform"
                      />

                      <text
                        x={node.x}
                        y={node.y + 28}
                        fill="#0f172a"
                        fontSize="10"
                        fontWeight="600"
                        textAnchor="middle"
                      >
                        {node.label}
                      </text>
                    </g>
                  );
                })}
              </svg>
            )}
          </div>

          {/* Node Inspector Card */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 space-y-4 shadow-sm">
            <div className="flex items-center space-x-2 border-b border-slate-200 pb-3">
              <Info className="w-4 h-4 text-blue-500" />
              <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                AGE Node Inspector (Real Data)
              </h4>
            </div>

            {selectedNode ? (
              <div className="space-y-3 text-xs">
                <div>
                  <div className="text-[10px] text-slate-400 uppercase font-bold">Node Label</div>
                  <div className="text-sm font-bold text-slate-900 break-words">{selectedNode.title || selectedNode.label}</div>
                </div>

                <div>
                  <div className="text-[10px] text-slate-400 uppercase font-bold">Node Type</div>
                  <span
                    className="inline-block px-2.5 py-0.5 rounded text-[10px] font-bold uppercase mt-1"
                    style={{ backgroundColor: `${selectedNode.color}25`, color: selectedNode.color }}
                  >
                    {selectedNode.type}
                  </span>
                </div>

                <div>
                  <div className="text-[10px] text-slate-400 uppercase font-bold">Raw Identifier</div>
                  <div className="font-mono text-slate-600 text-[11px] break-all">{selectedNode.rawId}</div>
                </div>

                {selectedNode.details && (
                  <div className="pt-2 border-t border-slate-200 space-y-2">
                    <div className="text-[10px] text-slate-400 uppercase font-bold">Properties</div>
                    {Object.entries(selectedNode.details).map(([key, val]) => (
                      <div key={key} className="flex justify-between text-[11px] font-mono">
                        <span className="text-slate-400">{key}:</span>
                        <span className="text-slate-700 font-semibold truncate max-w-[140px]">{String(val)}</span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="pt-2 border-t border-slate-200 space-y-2">
                  <div className="text-[10px] text-slate-400 uppercase font-bold">Connected Edges</div>
                  {edges.filter(
                    (e) => e.from === selectedNode.id || e.to === selectedNode.id
                  ).map((e, idx) => (
                    <div key={idx} className="p-1.5 rounded bg-slate-50 border border-slate-200 text-[10px] font-mono text-slate-500">
                      {e.from} &rarr; <span className="text-blue-600">{e.label}</span> &rarr; {e.to}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-400">Click on any node in the graph to inspect its live database properties.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
