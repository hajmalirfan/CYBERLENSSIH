import React, { useState } from 'react';
import { Network, Info, ShieldAlert, Cpu } from 'lucide-react';
import { ATTACK_GRAPH_NODES, ATTACK_GRAPH_EDGES } from '../data/mockData';

export default function AttackGraph() {
  const [selectedNode, setSelectedNode] = useState(ATTACK_GRAPH_NODES[0]);

  return (
    <div className="space-y-4">
      <div className="glass-card rounded-2xl p-6 border border-slate-800">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-4 mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <Network className="w-4 h-4 text-blue-400" />
              <span>Apache AGE Attack Path & Topology Graph</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Knowledge Graph linking Monitored Assets &rarr; Vulnerability Nodes &rarr; Threat Vectors &rarr; Financial & Regulatory Impact
            </p>
          </div>

          <div className="flex items-center space-x-3 text-xs">
            <span className="flex items-center space-x-1">
              <span className="w-3 h-3 rounded-full bg-blue-500 inline-block"></span>
              <span className="text-slate-400">Assets</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-3 h-3 rounded-full bg-red-500 inline-block"></span>
              <span className="text-slate-400">Vulnerabilities</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-3 h-3 rounded-full bg-purple-500 inline-block"></span>
              <span className="text-slate-400">Threats</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-3 h-3 rounded-full bg-pink-500 inline-block"></span>
              <span className="text-slate-400">Financial Impact</span>
            </span>
          </div>
        </div>

        {/* Graph Canvas Visualizer */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* Interactive SVG Graph */}
          <div className="lg:col-span-3 bg-slate-950/80 border border-slate-800/80 rounded-2xl p-4 relative overflow-hidden min-h-[460px] flex items-center justify-center">
            <svg className="w-full h-full min-h-[440px]" viewBox="0 0 920 600">
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
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569" />
                </marker>
              </defs>

              {/* Render Edges */}
              {ATTACK_GRAPH_EDGES.map((edge, i) => {
                const source = ATTACK_GRAPH_NODES.find((n) => n.id === edge.from);
                const target = ATTACK_GRAPH_NODES.find((n) => n.id === edge.to);
                if (!source || !target) return null;
                const isHighlighted = selectedNode && (selectedNode.id === source.id || selectedNode.id === target.id);

                return (
                  <g key={i}>
                    <line
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke={isHighlighted ? '#60a5fa' : '#334155'}
                      strokeWidth={isHighlighted ? 2.5 : 1.5}
                      strokeDasharray={edge.label === 'BUILT_FROM' ? '4,4' : 'none'}
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
              {ATTACK_GRAPH_NODES.map((node) => {
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
                      y={node.y + 30}
                      fill="#e2e8f0"
                      fontSize="11"
                      fontWeight="600"
                      textAnchor="middle"
                    >
                      {node.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Node Inspector Card */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
              <Info className="w-4 h-4 text-blue-400" />
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Graph Node Inspector
              </h4>
            </div>

            {selectedNode ? (
              <div className="space-y-3 text-xs">
                <div>
                  <div className="text-[10px] text-slate-500 uppercase font-bold">Node Label</div>
                  <div className="text-base font-bold text-slate-100">{selectedNode.label}</div>
                </div>

                <div>
                  <div className="text-[10px] text-slate-500 uppercase font-bold">AGE Vertex ID</div>
                  <div className="font-mono text-slate-300 text-[11px]">{selectedNode.id}</div>
                </div>

                <div>
                  <div className="text-[10px] text-slate-500 uppercase font-bold">Node Class</div>
                  <span
                    className="inline-block px-2.5 py-0.5 rounded text-[10px] font-bold uppercase mt-1"
                    style={{ backgroundColor: `${selectedNode.color}25`, color: selectedNode.color }}
                  >
                    {selectedNode.type}
                  </span>
                </div>

                <div className="pt-2 border-t border-slate-800 space-y-2">
                  <div className="text-[10px] text-slate-500 uppercase font-bold">Connected Edges</div>
                  {ATTACK_GRAPH_EDGES.filter(
                    (e) => e.from === selectedNode.id || e.to === selectedNode.id
                  ).map((e, idx) => (
                    <div key={idx} className="p-2 rounded bg-slate-950 text-[11px] font-mono text-slate-400">
                      {e.from} &rarr; <span className="text-blue-400">{e.label}</span> &rarr; {e.to}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500">Click on any node in the graph to inspect its properties and relationships.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
