import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { X, ArrowRight, ArrowLeft } from 'lucide-react';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    ReferenceLine,
    Scatter
} from 'recharts';

interface Packet {
    id: number;
    timestamp: string;
    seq: number;
    ack: number;
    flags: string;
    payload_len: number;
    payload: string;
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

    // Transform packets for visualization
    const chartData = packets.map((pkt, index) => {
        const isClientToServer = true; // We need to infer this, but for now assuming all are relative. 
        // Actually, we need source IP to know direction. 
        // But the Packet model doesn't store SourceIP per packet (optimization).
        // Wait, the backend *does* know. We should probably add 'direction' or 'is_client' to the Packet model
        // or just use the fact that we have ClientIP in the parent component.
        // For this MVP, let's assume we can't easily distinguish without SourceIP on the packet.

        // FIX: We need SourceIP on the packet model to do this correctly.
        // For now, let's simulate a "ping-pong" based on Seq/Ack or just alternate for demo?
        // No, that's misleading.

        // Let's use a simple heuristic: 
        // If it's the first packet, it's Client -> Server (SYN).
        // If the Ack matches the previous Seq + Len, it's a response.

        return {
            time: new Date(pkt.timestamp).getTime(),
            index,
            seq: pkt.seq,
            ack: pkt.ack,
            flags: pkt.flags,
            len: pkt.payload_len,
            // direction: ... 
        };
    });

    // Since we lack SourceIP on the packet model, we can't build a TRUE ladder diagram yet.
    // I will implement a "Sequence/Time" chart instead which is still very useful for timeouts.

    return (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-8">
            <div className="bg-slate-900 border border-slate-700 w-full max-w-6xl h-[80vh] rounded-xl flex flex-col shadow-2xl">
                <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-800/50 rounded-t-xl">
                    <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                        Time Sequence Analysis <span className="text-slate-500 text-sm font-normal">Stream {streamId}</span>
                    </h2>
                    <button onClick={onClose} className="text-slate-400 hover:text-white">
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <div className="flex-1 p-6">
                    {loading ? (
                        <div className="text-center text-slate-400">Loading packet data...</div>
                    ) : (
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={chartData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                <XAxis
                                    dataKey="time"
                                    type="number"
                                    domain={['auto', 'auto']}
                                    tickFormatter={(unixTime) => new Date(unixTime).toLocaleTimeString()}
                                    stroke="#94a3b8"
                                />
                                <YAxis stroke="#94a3b8" label={{ value: 'Sequence Number', angle: -90, position: 'insideLeft' }} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#475569', color: '#f1f5f9' }}
                                    labelFormatter={(label) => new Date(label).toLocaleTimeString()}
                                />
                                <Line type="stepAfter" dataKey="seq" stroke="#3b82f6" strokeWidth={2} dot={false} name="Sequence" />
                                <Line type="stepAfter" dataKey="ack" stroke="#10b981" strokeWidth={2} dot={false} name="Acknowledgement" />
                            </LineChart>
                        </ResponsiveContainer>
                    )}
                    <div className="mt-4 text-center text-slate-500 text-sm">
                        Visualizing Sequence (Blue) vs Acknowledgement (Green) progress over time.
                        Flat lines indicate delays/timeouts. Vertical jumps indicate data transfer.
                    </div>
                </div>
            </div>
        </div>
    );
};
