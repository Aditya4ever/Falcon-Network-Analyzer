import React, { useMemo } from 'react';
import ReactFlow, {
    Background,
    Controls,
    Node,
    Edge,
    MarkerType
} from 'reactflow';
import 'reactflow/dist/style.css';

interface Stream {
    id: string;
    client_ip: string;
    server_ip: string;
    protocol: string;
    severity: string;
}

interface TopologyMapProps {
    streams: Stream[];
    onInspectStream: (id: string) => void;
}

const TopologyMap: React.FC<TopologyMapProps> = ({ streams, onInspectStream }) => {
    const { nodes, edges } = useMemo(() => {
        const uniqueIPs = new Set<string>();
        const ipNodes: Node[] = [];
        const ipEdges: Edge[] = [];

        // 1. Identify Unique IPs (Nodes)
        streams.forEach(s => {
            uniqueIPs.add(s.client_ip);
            uniqueIPs.add(s.server_ip);
        });

        // 2. Create Nodes
        Array.from(uniqueIPs).forEach((ip, index) => {
            ipNodes.push({
                id: ip,
                data: { label: ip },
                position: { x: (index % 5) * 200, y: Math.floor(index / 5) * 150 }, // Simple grid layout
                style: {
                    background: '#1e293b',
                    color: '#fff',
                    border: '1px solid #475569',
                    borderRadius: '8px',
                    padding: '10px',
                    width: 150,
                    textAlign: 'center'
                },
            });
        });

        // 3. Create Edges (Connections)
        streams.forEach(s => {
            const edgeId = `${s.client_ip}-${s.server_ip}-${s.protocol}`;
            const isCritical = s.severity === 'critical';

            ipEdges.push({
                id: s.id,
                data: { streamId: s.id },
                source: s.client_ip,
                target: s.server_ip,
                label: s.protocol,
                animated: isCritical, // Animate critical paths
                style: {
                    stroke: isCritical ? '#ef4444' : '#64748b',
                    strokeWidth: isCritical ? 2 : 1
                },
                markerEnd: {
                    type: MarkerType.ArrowClosed,
                    color: isCritical ? '#ef4444' : '#64748b',
                },
            });
        });

        return { nodes: ipNodes, edges: ipEdges };
    }, [streams]);

    return (
        <div style={{ height: 500, border: '1px solid #334155', borderRadius: '8px', marginTop: '20px' }}>
            <ReactFlow
                nodes={nodes}
                edges={edges}
                fitView
                attributionPosition="bottom-right"
                onEdgeClick={(_, edge) => {
                    if (edge.data && edge.data.streamId) {
                        onInspectStream(edge.data.streamId);
                    }
                }}
            >
                <Background color="#334155" gap={16} />
                <Controls />
            </ReactFlow>
        </div>
    );
};

export default TopologyMap;
