import React, { useEffect, useState, useRef } from 'react';
import axios from 'axios';
import { X, ArrowDown, ZoomIn, ZoomOut } from 'lucide-react';

interface Packet {
    id: number;
    timestamp: string;
    seq: number;
    ack: number;
    flags: string;
    payload_len: number;
    src_ip: string;
    dst_ip: string;
    window_size: number;
}

interface LadderDiagramProps {
    streamId: string;
    clientIp: string;
    serverIp: string;
    onClose: () => void;
}

export const LadderDiagram: React.FC<LadderDiagramProps> = ({ streamId, clientIp, serverIp, onClose }) => {
    const [packets, setPackets] = useState<Packet[]>([]);
    const [loading, setLoading] = useState(true);
    const [scale, setScale] = useState(1);
    const containerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const fetchPackets = async () => {
            try {
                const res = await axios.get(`/api/stream/${streamId}/packets`);
                setPackets(res.data);
                setLoading(false);
            } catch (err) {
                console.error("Failed to fetch packets", err);
                setLoading(false);
            }
        };
        fetchPackets();
    }, [streamId]);

    const ROW_HEIGHT = 40;
    const SVG_WIDTH = 800;
    const LINE_X_CLIENT = 200;
    const LINE_X_SERVER = 600;

    return (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-8">
            <div className="bg-slate-900 border border-slate-700 w-full max-w-6xl h-[90vh] rounded-xl flex flex-col shadow-2xl">
                {/* Header */}
                <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-800/50 rounded-t-xl">
                    <div className="flex items-center gap-4">
                        <h2 className="text-xl font-semibold text-white">Flow Sequence</h2>
                        <div className="flex gap-2">
                            <button onClick={() => setScale(s => Math.min(s + 0.2, 2))} className="p-1 hover:bg-slate-700 rounded"><ZoomIn size={16} /></button>
                            <button onClick={() => setScale(s => Math.max(s - 0.2, 0.5))} className="p-1 hover:bg-slate-700 rounded"><ZoomOut size={16} /></button>
                        </div>
                    </div>
                    <button onClick={onClose} className="text-slate-400 hover:text-white"><X className="w-6 h-6" /></button>
                </div>

                {/* Legend / Headers */}
                <div className="grid grid-cols-2 text-center py-2 bg-slate-800/30 border-b border-slate-700 font-mono text-sm text-blue-300 font-bold">
                    <div>{clientIp} (Client)</div>
                    <div>{serverIp} (Server)</div>
                </div>

                {/* Scrollable Diagram */}
                <div className="flex-1 overflow-auto bg-slate-900 relative" ref={containerRef}>
                    {loading ? (
                        <div className="absolute inset-0 flex items-center justify-center text-slate-400">Loading packets...</div>
                    ) : (
                        <div style={{ height: packets.length * ROW_HEIGHT * scale + 100, width: '100%', minWidth: SVG_WIDTH }}>
                            <svg width="100%" height="100%">
                                <defs>
                                    <marker id="arrow-right" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
                                        <path d="M0,0 L0,6 L9,3 z" fill="#64748b" />
                                    </marker>
                                    <marker id="arrow-left" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
                                        <path d="M0,0 L0,6 L9,3 z" fill="#64748b" />
                                    </marker>
                                </defs>

                                {/* Vertical Timelines */}
                                <line x1={LINE_X_CLIENT} y1={0} x2={LINE_X_CLIENT} y2="100%" stroke="#334155" strokeWidth="2" strokeDasharray="5,5" />
                                <line x1={LINE_X_SERVER} y1={0} x2={LINE_X_SERVER} y2="100%" stroke="#334155" strokeWidth="2" strokeDasharray="5,5" />

                                {packets.map((pkt, i) => {
                                    const y = (i + 1) * ROW_HEIGHT * scale;
                                    const isC2S = pkt.src_ip === clientIp;
                                    const startX = isC2S ? LINE_X_CLIENT : LINE_X_SERVER;
                                    const endX = isC2S ? LINE_X_SERVER : LINE_X_CLIENT;
                                    const color = pkt.flags.includes('R') ? '#ef4444' : (pkt.flags.includes('S') ? '#22c55e' : '#94a3b8');

                                    // Delta Time (simplified)
                                    const prevTime = i > 0 ? new Date(packets[i - 1].timestamp).getTime() : new Date(pkt.timestamp).getTime();
                                    const currTime = new Date(pkt.timestamp).getTime();
                                    const delta = currTime - prevTime;

                                    return (
                                        <g key={pkt.id} className="hover:opacity-100 opacity-90 transition-opacity group">
                                            {/* Time Label on Left */}
                                            <text x={LINE_X_CLIENT - 20} y={y + 5} textAnchor="end" fill="#64748b" fontSize="10" fontFamily="monospace">
                                                {new Date(pkt.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}.{(new Date(pkt.timestamp).getMilliseconds()).toString().padStart(3, '0')}
                                                {delta > 0 && ` (+${delta}ms)`}
                                            </text>

                                            {/* Arrow Line */}
                                            <line
                                                x1={startX} y1={y}
                                                x2={endX + (isC2S ? -10 : 10)} y2={y}
                                                stroke={color}
                                                strokeWidth="1.5"
                                                markerEnd={isC2S ? "url(#arrow-right)" : "url(#arrow-left)"}
                                            />

                                            {/* Flag/Seq Label */}
                                            <rect
                                                x={(LINE_X_CLIENT + LINE_X_SERVER) / 2 - 100}
                                                y={y - 10}
                                                width="200"
                                                height="16"
                                                rx="4"
                                                fill="#1e293b"
                                            />
                                            <text
                                                x={(LINE_X_CLIENT + LINE_X_SERVER) / 2}
                                                y={y + 2}
                                                textAnchor="middle"
                                                fill={color}
                                                fontSize="11"
                                                fontFamily="monospace"
                                                fontWeight="bold"
                                            >
                                                [{pkt.flags}] Seq={pkt.seq} Len={pkt.payload_len}
                                            </text>
                                        </g>
                                    );
                                })}
                            </svg>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};
