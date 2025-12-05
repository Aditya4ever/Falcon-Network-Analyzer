import React, { useState } from 'react';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';
import { FileDown, Loader2 } from 'lucide-react';

interface ReportGeneratorProps {
    analysisId: string;
    targetRef: React.RefObject<HTMLDivElement>;
}

export const ReportGenerator: React.FC<ReportGeneratorProps> = ({ analysisId, targetRef }) => {
    const [generating, setGenerating] = useState(false);

    const generateReport = async () => {
        if (!targetRef.current) return;
        setGenerating(true);

        try {
            // Capture the dashboard
            const canvas = await html2canvas(targetRef.current, {
                scale: 2, // Higher quality
                backgroundColor: '#0f172a', // Match slate-900
                logging: false,
                useCORS: true
            });

            const imgData = canvas.toDataURL('image/png');

            // Calculate PDF dimensions (A4)
            const pdf = new jsPDF('p', 'mm', 'a4');
            const pdfWidth = pdf.internal.pageSize.getWidth();
            const pdfHeight = pdf.internal.pageSize.getHeight();

            const imgWidth = pdfWidth;
            const imgHeight = (canvas.height * imgWidth) / canvas.width;

            // Add Title
            pdf.setFontSize(20);
            pdf.setTextColor(40, 40, 40);
            pdf.text(`Network Analysis Report: ${analysisId}`, 10, 15);

            pdf.setFontSize(10);
            pdf.setTextColor(100, 100, 100);
            pdf.text(`Generated: ${new Date().toLocaleString()}`, 10, 22);

            // Add Image (splitting pages if needed, but for now simple fit)
            // If height > page, we might need multi-page logic. 
            // For MVP, let's just scale to fit or add as one big image if it fits.

            if (imgHeight < pdfHeight - 30) {
                pdf.addImage(imgData, 'PNG', 0, 30, imgWidth, imgHeight);
            } else {
                // Multi-page logic (simplified)
                let heightLeft = imgHeight;
                let position = 30;

                pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
                heightLeft -= (pdfHeight - 30);

                while (heightLeft >= 0) {
                    position = heightLeft - imgHeight;
                    pdf.addPage();
                    pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
                    heightLeft -= pdfHeight;
                }
            }

            pdf.save(`falcon-report-${analysisId}.pdf`);
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
