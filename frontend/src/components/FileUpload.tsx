import React, { useCallback, useState } from 'react';
import { Upload, FileText, AlertCircle, CheckCircle } from 'lucide-react';
import axios from 'axios';

interface FileUploadProps {
    onUploadComplete: (id: string) => void;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onUploadComplete }) => {
    const [isDragging, setIsDragging] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleDrag = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === 'dragenter' || e.type === 'dragover') {
            setIsDragging(true);
        } else if (e.type === 'dragleave') {
            setIsDragging(false);
        }
    }, []);

    const uploadFile = async (file: File) => {
        setUploading(true);
        setError(null);

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await axios.post('/api/upload', formData, {
                headers: { 'Content-Type': 'multipart/form-data' },
            });
            onUploadComplete(response.data.id);
        } catch (err) {
            setError('Upload failed. Please try again.');
            console.error(err);
        } finally {
            setUploading(false);
        }
    };

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);

        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            uploadFile(e.dataTransfer.files[0]);
        }
    }, []);

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            uploadFile(e.target.files[0]);
        }
    };

    return (
        <div className="w-full max-w-xl mx-auto mt-10">
            <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                className={`
          relative border-2 border-dashed rounded-xl p-10 text-center transition-all duration-200
          ${isDragging
                        ? 'border-blue-500 bg-blue-500/10'
                        : 'border-slate-700 hover:border-slate-600 bg-slate-800/50'
                    }
        `}
            >
                <input
                    type="file"
                    className="hidden"
                    id="file-upload"
                    onChange={handleFileSelect}
                    accept=".pcap,.pcapng,.cap"
                />

                <div className="flex flex-col items-center gap-4">
                    <div className="p-4 rounded-full bg-slate-800 ring-1 ring-slate-700">
                        {uploading ? (
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
                        ) : (
                            <Upload className="w-8 h-8 text-blue-400" />
                        )}
                    </div>

                    <div>
                        <h3 className="text-lg font-medium text-slate-200">
                            {uploading ? 'Uploading & Analyzing...' : 'Upload PCAP File'}
                        </h3>
                        <p className="text-sm text-slate-400 mt-1">
                            Drag and drop or <label htmlFor="file-upload" className="text-blue-400 hover:text-blue-300 cursor-pointer font-medium">browse</label>
                        </p>
                    </div>

                    {error && (
                        <div className="flex items-center gap-2 text-red-400 text-sm bg-red-400/10 px-3 py-2 rounded-lg">
                            <AlertCircle className="w-4 h-4" />
                            {error}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};
