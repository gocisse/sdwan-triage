// Drag and drop file upload component

import { useState, useCallback, useRef } from 'react';
import { Upload, File, X, AlertCircle } from 'lucide-react';
import { formatBytes } from '../utils';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  isUploading: boolean;
  progress: number;
  error: string | null;
  onReset: () => void;
}

export function FileUpload({ 
  onFileSelect, 
  isUploading, 
  progress, 
  error,
  onReset 
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      setSelectedFile(file);
      onFileSelect(file);
    }
  }, [onFileSelect]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      setSelectedFile(file);
      onFileSelect(file);
    }
  }, [onFileSelect]);

  const handleClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleClear = useCallback(() => {
    setSelectedFile(null);
    onReset();
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }, [onReset]);

  return (
    <div className="w-full">
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".pcap,.pcapng,.cap"
        onChange={handleFileInput}
        className="hidden"
      />

      {/* Drop zone */}
      <div
        onClick={!isUploading ? handleClick : undefined}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={!isUploading ? handleDrop : undefined}
        className={`
          relative border-2 border-dashed rounded-xl p-8 sm:p-12
          transition-all duration-200 cursor-pointer
          ${isDragging 
            ? 'border-blue-500 bg-blue-500/10' 
            : 'border-slate-600 hover:border-slate-500 hover:bg-slate-800/50'
          }
          ${isUploading ? 'cursor-not-allowed opacity-75' : ''}
          ${error ? 'border-red-500/50' : ''}
        `}
      >
        {/* Upload icon and text */}
        {!selectedFile && !isUploading && (
          <div className="flex flex-col items-center text-center">
            <div className="w-16 h-16 bg-slate-700 rounded-full flex items-center justify-center mb-4">
              <Upload className="w-8 h-8 text-slate-400" />
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">
              Drop your PCAP file here
            </h3>
            <p className="text-sm text-slate-400 mb-4">
              or click to browse
            </p>
            <div className="flex flex-wrap justify-center gap-2">
              <span className="px-2 py-1 bg-slate-700 rounded text-xs text-slate-300">.pcap</span>
              <span className="px-2 py-1 bg-slate-700 rounded text-xs text-slate-300">.pcapng</span>
              <span className="px-2 py-1 bg-slate-700 rounded text-xs text-slate-300">.cap</span>
            </div>
            <p className="text-xs text-slate-500 mt-4">
              Maximum file size: 500MB
            </p>
          </div>
        )}

        {/* Selected file display */}
        {selectedFile && !isUploading && !error && (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <File className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <p className="font-medium text-white">{selectedFile.name}</p>
                <p className="text-sm text-slate-400">{formatBytes(selectedFile.size)}</p>
              </div>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleClear();
              }}
              className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-slate-400" />
            </button>
          </div>
        )}

        {/* Upload progress */}
        {isUploading && (
          <div className="flex flex-col items-center">
            <div className="w-full max-w-xs mb-4">
              <div className="flex justify-between text-sm mb-2">
                <span className="text-slate-400">Uploading...</span>
                <span className="text-white font-medium">{progress}%</span>
              </div>
              <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-blue-500 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
            {selectedFile && (
              <p className="text-sm text-slate-400">{selectedFile.name}</p>
            )}
          </div>
        )}

        {/* Error display */}
        {error && (
          <div className="flex items-center gap-3 text-red-400">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <div>
              <p className="font-medium">Upload failed</p>
              <p className="text-sm text-red-400/80">{error}</p>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleClear();
              }}
              className="ml-auto px-3 py-1 bg-red-500/20 hover:bg-red-500/30 rounded-lg text-sm transition-colors"
            >
              Try again
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
