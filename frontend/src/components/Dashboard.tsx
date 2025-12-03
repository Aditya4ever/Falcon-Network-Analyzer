import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { AlertTriangle, CheckCircle, Clock, Activity } from 'lucide-react';

interface DashboardProps {
    analysisId: string;
}

interface Stream {
    id: string;
    client_ip: string;
    server_ip: string;
    server_port: number;
    protocol: string;
    severity: 'normal' | 'warning' | 'critical';
    stats: {
        packet_count: number;
        retransmission_count: number;
        reset_count: number;
        has_timeout: boolean;
    };
    analysis: string[];
}

interface AnalysisResult {
    status: string;
    summary: {
        total_streams: number;
        issues_found: number;
    };
    streams: Stream[];
}

export const Dashboard: React.FC<DashboardProps> = ({ analysisId }) => {
    const [data, setData] = useState<AnalysisResult | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const pollAnalysis = async () => {
            try {
                const res = await axios.get(`/api/analysis/${analysisId}`);
                if (res.data.status === 'complete') {
                    setData(res.data);
                    setLoading(false);
                } else {
                    // Poll again in 1s
                    setTimeout(pollAnalysis, 1000);
                }
            } catch (err) {
                console.error(err);
                setLoading(false);
            }
        };
        pollAnalysis();
    }, [analysisId]);

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mb-4" />
                <p className="text-slate-400">Analyzing network traffic...</p>
            </div>
        );
    }

    if (!data) return <div>Failed to load analysis</div>;

    const criticalStreams = data.streams.filter(s => s.severity === 'critical');
    const warningStreams = data.streams.filter(s => s.severity === 'warning');

    return (
        <div className="max-w-6xl mx-auto p-6 space-y-8">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card
                    title="Total Streams"
                    value={data.summary.total_streams}
                    icon={<Activity className="text-blue-400" />}
                />
                <Card
                    title="Critical Issues"
                    value={criticalStreams.length}
                    icon={<AlertTriangle className="text-red-400" />}
                    className="border-red-500/20 bg-red-500/5"
                />
                <Card
                    title="Warnings"
                    value={warningStreams.length}
                    icon={<Clock className="text-yellow-400" />}
                />
            </div>

            {/* Issues List */}
            <div className="space-y-4">
                <h2 className="text-xl font-semibold text-slate-100">Detected Issues</h2>
                {criticalStreams.length === 0 && warningStreams.length === 0 && (
                    <div className="p-8 text-center bg-slate-800/50 rounded-xl border border-slate-700">
                        <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-3" />
                        <p className="text-slate-300">No significant issues detected.</p>
                    </div>
                )}

                {criticalStreams.map(stream => (
                    <StreamCard key={stream.id} stream={stream} />
                ))}
                {warningStreams.map(stream => (
                    <StreamCard key={stream.id} stream={stream} />
                ))}
            </div>
        </div>
    );
};

const Card = ({ title, value, icon, className = "" }: any) => (
    <div className={`bg-slate-800/50 border border-slate-700 rounded-xl p-6 ${className}`}>
        <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm font-medium">{title}</span>
            {icon}
        </div>
        <div className="text-3xl font-bold text-slate-100">{value}</div>
    </div>
);

const StreamCard = ({ stream }: { stream: Stream }) => (
    <div className={`
    p-4 rounded-lg border 
    ${stream.severity === 'critical' ? 'bg-red-500/5 border-red-500/20' : 'bg-yellow-500/5 border-yellow-500/20'}
  `}>
        <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-3">
                <span className={`px-2 py-1 rounded text-xs font-bold uppercase ${stream.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'
                    }`}>
                    {stream.severity}
                </span>
                <span className="font-mono text-slate-300">
                    {stream.client_ip} → {stream.server_ip}:{stream.server_port}
                </span>
            </div>
            <span className="text-xs text-slate-500">{stream.protocol}</span>
        </div>

        <div className="space-y-1 mt-3">
            {stream.analysis.map((issue, idx) => (
                <div key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                    <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-current opacity-60" />
                    {issue}
                </div>
            ))}
        </div>

        <div className="mt-4 flex gap-6 text-xs text-slate-500 font-mono border-t border-slate-700/50 pt-3">
            <span>Pkts: {stream.stats.packet_count}</span>
            <span>Retrans: {stream.stats.retransmission_count}</span>
            <span>RSTs: {stream.stats.reset_count}</span>
        </div>
    </div>
);
