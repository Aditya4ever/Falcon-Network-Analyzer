import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { AlertTriangle, CheckCircle, Clock, Activity, Network } from 'lucide-react';
import { StreamList } from './StreamList';
import TopologyMap from './TopologyMap';
import { PacketViewer } from './PacketViewer';
import { LadderDiagram } from './LadderDiagram';
import { ReportGenerator } from './ReportGenerator';

interface DashboardProps {
    analysisId: string;
    onReset: () => void;
}

interface Stream {
    id: string;
    client_ip: string;
    server_ip: string;
    server_port: number;
    protocol: string;
    severity: 'normal' | 'warning' | 'critical';
    packet_count: number;
    retransmission_count: number;
    reset_count: number;
    has_timeout: boolean;
    analysis_issues: string; // JSON string
}

interface AnalysisResult {
    status: string;
    summary: {
        total_streams: number;
        issues_found: number;
    };
    streams: Stream[];
}

export const Dashboard: React.FC<DashboardProps> = ({ analysisId, onReset }) => {
    const [data, setData] = useState<AnalysisResult | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const dashboardRef = React.useRef<HTMLDivElement>(null);

    // Filter State
    const [filterSource, setFilterSource] = useState('');
    const [filterDest, setFilterDest] = useState('');
    const [filterProtocol, setFilterProtocol] = useState('');
    const [viewingStreamId, setViewingStreamId] = useState<string | null>(null);
    const [ladderStream, setLadderStream] = useState<Stream | null>(null);

    useEffect(() => {
        const pollAnalysis = async () => {
            try {
                const res = await axios.get(`/api/analysis/${analysisId}`);
                if (res.data.status === 'complete') {
                    console.log("Analysis complete. Data received:", res.data);
                    setData(res.data);
                    setLoading(false);
                } else {
                    // Poll again in 1s
                    setTimeout(pollAnalysis, 1000);
                }
            } catch (err: any) {
                console.error(err);
                // If 404, it means analysis is gone. If Network Error, backend might be down.
                const msg = err.response?.status === 404
                    ? "Analysis not found (Backend might have restarted)"
                    : (err.message || "Failed to load analysis");
                setError(msg);
                setLoading(false);
            }
        };
        if (analysisId) {
            pollAnalysis();
        }
    }, [analysisId]);

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mb-4" />
                <p className="text-slate-400">Analyzing network traffic...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="p-8 text-center">
                <div className="text-red-400 text-lg mb-4">{error}</div>
                <button
                    onClick={onReset}
                    className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-white transition-colors"
                >
                    Start New Analysis
                </button>
            </div>
        );
    }

    if (!data) return <div>Loading...</div>;

    // Filtering Logic
    const filteredStreams = (data.streams || []).filter(stream => {
        const matchSource = stream.client_ip.includes(filterSource);
        const matchDest = stream.server_ip.includes(filterDest);
        const matchProto = stream.protocol.toLowerCase().includes(filterProtocol.toLowerCase());
        return matchSource && matchDest && matchProto;
    });

    // Limit to 50 unless searching
    const displayStreams = (filterSource || filterDest || filterProtocol)
        ? filteredStreams
        : filteredStreams.slice(0, 50);

    const criticalCount = data.streams.filter(s => s.severity === 'critical').length;
    const warningCount = data.streams.filter(s => s.severity === 'warning').length;

    return (
        <div ref={dashboardRef} className="max-w-6xl mx-auto p-6 space-y-8">
            <div className="flex justify-end mb-4">
                <ReportGenerator analysisId={analysisId} targetRef={dashboardRef} />
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card
                    title="Total Streams"
                    value={data.summary.total_streams}
                    icon={<Activity className="text-blue-400" />}
                />
                <Card
                    title="Critical Issues"
                    value={criticalCount}
                    icon={<AlertTriangle className="text-red-400" />}
                    className="border-red-500/20 bg-red-500/5"
                />
                <Card
                    title="Warnings"
                    value={warningCount}
                    icon={<Clock className="text-yellow-400" />}
                />
            </div>

            {/* Topology Map */}
            {filteredStreams.length > 0 && (
                <div className="mb-8">
                    <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                        <Network className="w-5 h-5 text-purple-400" />
                        Network Topology
                    </h2>
                    <TopologyMap streams={filteredStreams} onInspectStream={setViewingStreamId} />
                </div>
            )}

            {/* Filters */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 flex gap-4">
                <input
                    type="text"
                    placeholder="Filter Source IP"
                    className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-white w-full"
                    value={filterSource}
                    onChange={e => setFilterSource(e.target.value)}
                />
                <input
                    type="text"
                    placeholder="Filter Dest IP"
                    className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-white w-full"
                    value={filterDest}
                    onChange={e => setFilterDest(e.target.value)}
                />
                <input
                    type="text"
                    placeholder="Filter Protocol"
                    className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-white w-full"
                    value={filterProtocol}
                    onChange={e => setFilterProtocol(e.target.value)}
                />
            </div>

            {/* Stream List */}
            <div className="space-y-4">
                <div className="flex justify-between items-center">
                    <h2 className="text-xl font-semibold text-slate-100">Traffic Streams</h2>
                    <span className="text-sm text-slate-400">
                        Showing {displayStreams.length} of {filteredStreams.length} streams
                    </span>
                </div>
                <StreamList
                    streams={displayStreams}
                    onInspectStream={(id) => {
                        console.log("Dashboard: inspecting stream", id);
                        setViewingStreamId(id);
                    }}
                    onViewLadder={setLadderStream}
                />
            </div>

            {/* Packet Viewer Modal */}
            {viewingStreamId && (
                <PacketViewer
                    streamId={viewingStreamId}
                    stream={data?.streams.find(s => s.id === viewingStreamId)}
                    onClose={() => {
                        console.log("Closing PacketViewer");
                        setViewingStreamId(null);
                    }}
                />
            )}

            {/* Ladder Diagram Modal */}
            {ladderStream && (
                <LadderDiagram
                    streamId={ladderStream.id}
                    clientIp={ladderStream.client_ip}
                    serverIp={ladderStream.server_ip}
                    onClose={() => setLadderStream(null)}
                />
            )}
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
