import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { X, ArrowRight, ArrowLeft } from 'lucide-react';

interface Packet {
    id: number;
    timestamp: string;
    seq: number;
    ack: number;
    flags: string;
    payload_len: number;
    window_size: number;
    payload: string; // Base64 encoded by default in JSON? No, usually raw bytes need handling. Axios might return base64 string for []byte.
}

interface StreamSummary {
    id: string;
    client_ip: string;
    server_ip: string;
    protocol: string;
    analysis: string[];
}

interface PacketViewerProps {
    streamId: string;
    stream?: any; // Pass full stream object for context
    onClose: () => void;
}

export const PacketViewer: React.FC<PacketViewerProps> = ({ streamId, stream, onClose }) => {
    const [packets, setPackets] = useState<Packet[]>([]);
    const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        console.log("PacketViewer mounted for stream:", streamId);
        const fetchPackets = async () => {
            try {
                const res = await axios.get(`/api/stream/${streamId}/packets`);
                console.log("PacketViewer: fetched packets:", res.data.length);
                setPackets(res.data);
                if (res.data.length > 0) {
                    setSelectedPacket(res.data[0]);
                }
                setLoading(false);
            } catch (err) {
                console.error("Failed to fetch packets", err);
                setLoading(false);
            }
        };
        fetchPackets();
    }, [streamId]);

    const renderHex = (base64Payload: string) => {
        if (!base64Payload) return <div className="text-slate-500 italic">No Payload</div>;

        try {
            const binaryString = window.atob(base64Payload);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            const rows = [];
            for (let i = 0; i < bytes.length; i += 16) {
                const chunk = bytes.slice(i, i + 16);
                const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
                const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');

                rows.push(
                    <div key={i} className="flex font-mono text-sm">
                        <div className="w-16 text-slate-500 select-none">{i.toString(16).padStart(4, '0')}</div>
                        <div className="w-96 text-blue-300">{hex.padEnd(48, ' ')}</div>
                        <div className="w-48 text-slate-300 border-l border-slate-700 pl-4">{ascii}</div>
                    </div>
                );
            }
            return <div className="space-y-1">{rows}</div>;
        } catch (e) {
            return <div className="text-red-400">Error decoding payload</div>;
        }
    };

    return (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-8">
            <div className="bg-slate-900 border border-slate-700 w-full max-w-6xl h-[80vh] rounded-xl flex flex-col shadow-2xl">
                {/* Header */}
                <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-800/50 rounded-t-xl">
                    <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                        Packet Inspector
                        <span className="text-slate-500 text-sm font-normal">
                            {stream ? `${stream.client_ip} → ${stream.server_ip} (${stream.protocol})` : `Stream ${streamId}`}
                        </span>
                    </h2>
                    <button onClick={onClose} className="text-slate-400 hover:text-white">
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <div className="flex-1 flex overflow-hidden">
                    {/* Packet List (Left) */}
                    <div className="w-1/3 border-r border-slate-700 overflow-y-auto bg-slate-900/50">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-slate-800 text-slate-400 sticky top-0">
                                <tr>
                                    <th className="p-3 font-medium">#</th>
                                    <th className="p-3 font-medium">Time (Δ)</th>
                                    <th className="p-3 font-medium">Flags</th>
                                    <th className="p-3 font-medium">Win</th>
                                    <th className="p-3 font-medium">Len</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800">
                                {loading ? (
                                    <tr><td colSpan={4} className="p-4 text-center">Loading...</td></tr>
                                ) : packets.map((pkt, idx) => (
                                    <tr
                                        key={pkt.id}
                                        onClick={() => setSelectedPacket(pkt)}
                                        className={`cursor-pointer hover:bg-slate-800 transition-colors ${selectedPacket?.id === pkt.id ? 'bg-blue-900/30 border-l-2 border-blue-500' : ''}`}
                                    >
                                        <td className="p-3 text-slate-500">{idx + 1}</td>
                                        <td className="p-3 text-slate-300">
                                            {new Date(pkt.timestamp).toLocaleTimeString()}
                                            <span className="block text-xs text-slate-500">
                                                {idx > 0 ? `+${(new Date(pkt.timestamp).getTime() - new Date(packets[idx - 1].timestamp).getTime())}ms` : '0ms'}
                                            </span>
                                        </td>
                                        <td className="p-3">
                                            <span className={`px-2 py-0.5 rounded text-xs font-medium border ${pkt.flags.includes('RST') ? 'bg-red-900/30 text-red-300 border-red-800' :
                                                pkt.flags.includes('SYN') ? 'bg-green-900/30 text-green-300 border-green-800' :
                                                    pkt.flags.includes('FIN') ? 'bg-yellow-900/30 text-yellow-300 border-yellow-800' :
                                                        'bg-slate-800 text-slate-300 border-slate-700'
                                                }`}>
                                                {pkt.flags || "DATA"}
                                            </span>
                                        </td>
                                        <td className="p-3 text-slate-400 font-mono">{pkt.window_size}</td>
                                        <td className="p-3 text-slate-400">{pkt.payload_len}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Hex View (Right) */}
                    <div className="w-2/3 flex flex-col bg-slate-950">
                        {selectedPacket ? (
                            <>
                                <div className="p-4 border-b border-slate-800 bg-slate-900/30">
                                    <div className="flex gap-6 text-sm">
                                        <div>
                                            <span className="text-slate-500 block text-xs uppercase tracking-wider">Sequence</span>
                                            <span className="text-white font-mono">{selectedPacket.seq}</span>
                                        </div>
                                        <div>
                                            <span className="text-slate-500 block text-xs uppercase tracking-wider">Ack</span>
                                            <span className="text-white font-mono">{selectedPacket.ack}</span>
                                        </div>
                                        <div>
                                            <span className="text-slate-500 block text-xs uppercase tracking-wider">Payload Size</span>
                                            <span className="text-white font-mono">{selectedPacket.payload_len} bytes</span>
                                        </div>
                                        <div>
                                            <span className="text-slate-500 block text-xs uppercase tracking-wider">Window</span>
                                            <span className="text-white font-mono">{selectedPacket.window_size}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex-1 overflow-y-auto p-6 font-mono text-sm">
                                    {renderHex(selectedPacket.payload)}
                                </div>
                            </>
                        ) : (
                            <div className="flex-1 flex items-center justify-center text-slate-600">
                                Select a packet to view payload
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};
