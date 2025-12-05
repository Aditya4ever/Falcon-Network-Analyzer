import React, { useState } from 'react';
import { ChevronDown, ChevronRight, AlertCircle, Shield, Globe, Activity } from 'lucide-react';

interface StreamListProps {
    streams: any[];
    onInspectStream: (id: string) => void;
    onViewLadder: (stream: any) => void;
}

export const StreamList: React.FC<StreamListProps> = ({ streams, onInspectStream, onViewLadder }) => {
    const [expandedId, setExpandedId] = useState<string | null>(null);

    const toggleExpand = (id: string) => {
        console.log("Toggling expand for stream:", id);
        setExpandedId(expandedId === id ? null : id);
    };

    return (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
            <div className="grid grid-cols-12 gap-4 p-4 bg-slate-900/50 border-b border-slate-700 text-sm font-medium text-slate-400">
                <div className="col-span-1"></div>
                <div className="col-span-4">Source</div>
                <div className="col-span-4">Destination</div>
                <div className="col-span-2">Protocol</div>
                <div className="col-span-1">Issues</div>
            </div>

            <div className="divide-y divide-slate-700/50">
                {streams.map((stream) => (
                    <div key={stream.id} className="group">
                        <div
                            onClick={() => toggleExpand(stream.id)}
                            className={`
                grid grid-cols-12 gap-4 p-4 items-center cursor-pointer hover:bg-slate-700/30 transition-colors
                ${stream.severity === 'critical' ? 'bg-red-500/5' : ''}
              `}
                        >
                            <div className="col-span-1 flex justify-center">
                                {expandedId === stream.id ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                            </div>
                            <div className="col-span-4 font-mono text-sm text-slate-300">
                                {stream.client_ip}:{stream.client_port}
                            </div>
                            <div className="col-span-4 font-mono text-sm text-slate-300">
                                {stream.server_ip}:{stream.server_port}
                            </div>
                            <div className="col-span-2 flex items-center gap-2">
                                <Badge protocol={stream.protocol} />
                            </div>
                            <div className="col-span-1">
                                {stream.severity !== 'normal' && (
                                    <AlertCircle className={`w-5 h-5 ${stream.severity === 'critical' ? 'text-red-400' : 'text-yellow-400'}`} />
                                )}
                            </div>
                        </div>

                        {expandedId === stream.id && (
                            <div className="bg-slate-900/50 p-4 pl-16 border-t border-slate-700/50">
                                <div className="grid grid-cols-3 gap-6 mb-4">
                                    <Stat label="Packets" value={stream.packet_count} />
                                    <Stat label="Retransmissions" value={stream.retransmission_count} />
                                    <Stat label="Resets" value={stream.reset_count} />
                                </div>

                                {stream.analysis_issues && (
                                    <div className="space-y-2">
                                        <h4 className="text-xs font-semibold uppercase text-slate-500 tracking-wider">Analysis Findings</h4>
                                        {(() => {
                                            try {
                                                const issues = JSON.parse(stream.analysis_issues);
                                                return Array.isArray(issues) ? issues.map((issue: string, idx: number) => (
                                                    <div key={idx} className="flex items-center gap-2 text-sm text-red-300 bg-red-500/10 p-2 rounded">
                                                        <AlertCircle className="w-4 h-4" />
                                                        {issue}
                                                    </div>
                                                )) : null;
                                            } catch (e) {
                                                return null;
                                            }
                                        })()}
                                    </div>
                                )}

                                <div className="mt-4 flex justify-end">
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onViewLadder(stream);
                                        }}
                                        className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium rounded transition-colors flex items-center gap-2 mr-2"
                                    >
                                        <Activity className="w-4 h-4" />
                                        Time Sequence
                                    </button>
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            console.log("StreamList: Clicked Inspect for", stream.id);
                                            onInspectStream(stream.id);
                                        }}
                                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded transition-colors flex items-center gap-2"
                                    >
                                        <Shield className="w-4 h-4" />
                                        Inspect Packets
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
};

const Badge = ({ protocol }: { protocol: string }) => {
    let color = "bg-slate-600";
    let Icon = Activity;

    if (protocol === "TLS") { color = "bg-purple-500"; Icon = Shield; }
    if (protocol === "HTTP") { color = "bg-blue-500"; Icon = Globe; }
    if (protocol === "TCP") { color = "bg-slate-600"; }

    return (
        <span className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium text-white ${color}`}>
            <Icon className="w-3 h-3" />
            {protocol}
        </span>
    );
};

const Stat = ({ label, value }: { label: string, value: number }) => (
    <div>
        <div className="text-xs text-slate-500 mb-1">{label}</div>
        <div className="text-lg font-mono text-slate-200">{value}</div>
    </div>
);
