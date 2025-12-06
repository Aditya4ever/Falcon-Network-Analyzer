import React, { useState } from 'react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { FileDown, Loader2 } from 'lucide-react';

interface ReportGeneratorProps {
    analysisId: string;
    targetRef: React.RefObject<HTMLDivElement>;
    data?: any; // We'll pass the analysis data directly
}

export const ReportGenerator: React.FC<ReportGeneratorProps> = ({ analysisId, data }) => {
    const [generating, setGenerating] = useState(false);

    const generateReport = async () => {
        setGenerating(true);

        try {
            const doc = new jsPDF();
            const pageWidth = doc.internal.pageSize.getWidth();

            // --- Title Page ---
            doc.setFontSize(22);
            doc.setTextColor(40, 40, 40);
            doc.text("Expertise Network Analysis Report", 14, 20);

            doc.setFontSize(10);
            doc.setTextColor(100, 100, 100);
            doc.text(`Analysis ID: ${analysisId}`, 14, 28);
            doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 33);

            // --- Executive Summary ---
            doc.setDrawColor(200, 200, 200);
            doc.line(14, 38, pageWidth - 14, 38);

            if (data && data.summary) {
                doc.setFontSize(14);
                doc.setTextColor(0, 0, 0);
                doc.text("Executive Summary", 14, 48);

                doc.setFontSize(10);
                doc.setTextColor(60, 60, 60);
                doc.text(`Total Streams Analyzed: ${data.summary.total_streams}`, 14, 56);
                doc.text(`Issues Found: ${data.summary.issues_found}`, 14, 61);

                // Add Status Badge-like text
                const statusColor = data.status === 'complete' ? [0, 150, 0] : [200, 0, 0];
                doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
                doc.text(`Status: ${data.status.toUpperCase()}`, 14, 66);
            }

            // --- Issues Table ---
            if (data && data.streams) {
                doc.setTextColor(0, 0, 0);
                doc.setFontSize(14);
                doc.text("Identified Issues & Anomalies", 14, 80);

                // Filter for streams with issues
                const problematicStreams = data.streams.filter((s: any) => s.severity !== 'normal');

                const tableData = problematicStreams.map((s: any) => [
                    s.client_ip,
                    s.server_ip,
                    s.protocol,
                    s.severity.toUpperCase(),
                    `${s.packet_count} pkts`,
                    // Format analysis issues from JSON string or object
                    // Assuming analysis_issues is a JSON string based on our model
                    (typeof s.analysis_issues === 'string'
                        ? JSON.parse(s.analysis_issues || "[]").join(", ")
                        : (s.analysis_issues || []).join(", ")
                    ).substring(0, 50) + "..."
                ]);

                autoTable(doc, {
                    startY: 85,
                    head: [['Source', 'Dest', 'Proto', 'Severity', 'Size', 'Details']],
                    body: tableData,
                    theme: 'grid',
                    headStyles: { fillColor: [51, 65, 85] }, // Slate-700
                    styles: { fontSize: 8 },
                    columnStyles: {
                        5: { cellWidth: 60 }
                    }
                });
            }

            // --- Critical Stream Details (Limit to top 5) ---
            // Add a new page for detailed stream breakdown
            if (data && data.streams) {
                const criticalStreams = data.streams.filter((s: any) => s.severity === 'critical').slice(0, 5);

                if (criticalStreams.length > 0) {
                    doc.addPage();
                    doc.setFontSize(14);
                    doc.text("Critical Stream Details (Top 5)", 14, 20);

                    let yPos = 30;
                    criticalStreams.forEach((s: any, index: number) => {
                        doc.setFontSize(11);
                        doc.setTextColor(0, 0, 0);
                        doc.text(`Stream #${index + 1}: ${s.client_ip} -> ${s.server_ip} (${s.protocol})`, 14, yPos);

                        // Stream Stats
                        doc.setFontSize(9);
                        doc.setTextColor(80, 80, 80);
                        const issues = typeof s.analysis_issues === 'string'
                            ? JSON.parse(s.analysis_issues || "[]").join(", ")
                            : (s.analysis_issues || []).join(", ");

                        doc.text([
                            `• Severity: ${s.severity.toUpperCase()}`,
                            `• Issues: ${issues}`,
                            `• Retransmits: ${s.retransmission_count}`,
                            `• Timeouts: ${s.has_timeout ? 'Yes' : 'No'}`
                        ], 20, yPos + 6);

                        yPos += 35;
                    });
                }
            }

            doc.save(`falcon-report-${analysisId}.pdf`);
            console.log("Report generated successfully");

        } catch (err) {
            console.error("Report generation failed", err);
            alert("Failed to generate report");
        } finally {
            setGenerating(false);
        }
    };

    return (
        <button
            onClick={generateReport}
            disabled={generating}
            className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded transition-colors disabled:opacity-50"
        >
            {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileDown className="w-4 h-4" />}
            {generating ? 'Generating...' : 'Export Report'}
        </button>
    );
};
