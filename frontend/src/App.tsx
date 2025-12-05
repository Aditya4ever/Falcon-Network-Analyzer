import { useState, useEffect } from 'react';
import { FileUpload } from './components/FileUpload';
import { Dashboard } from './components/Dashboard';

function App() {
    const [analysisId, setAnalysisId] = useState<string | null>(null);

    return (
        <div className="min-h-screen bg-slate-900 text-slate-100">
            <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-10">
                <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center font-bold text-white">
                            F
                        </div>
                        <h1 className="font-semibold text-lg tracking-tight">Falcon Network Analyzer</h1>
                    </div>
                    {analysisId && (
                        <button
                            onClick={() => setAnalysisId(null)}
                            className="text-sm text-slate-400 hover:text-white transition-colors"
                        >
                            New Analysis
                        </button>
                    )}
                </div>
            </header>

            <main className="py-8">
                {!analysisId ? (
                    <div className="px-6">
                        <div className="text-center mb-12 mt-8">
                            <h2 className="text-3xl font-bold text-white mb-4">
                                Expert Network Analysis, Simplified
                            </h2>
                            <p className="text-slate-400 max-w-2xl mx-auto text-lg">
                                Upload your PCAP files to automatically detect complex network issues like
                                TCP timeouts, retransmissions, and application latency.
                            </p>
                        </div>
                        <FileUpload onUploadComplete={setAnalysisId} />
                    </div>
                ) : (
                    <Dashboard analysisId={analysisId} onReset={() => setAnalysisId(null)} />
                )}
            </main>
        </div>
    );
}

export default App;
