// Home page with file upload

import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileUpload } from '../components';
import { useFileUpload } from '../hooks';
import { startAnalysis } from '../api/client';
import { Loader2, Play, Info } from 'lucide-react';

export function HomePage() {
  const navigate = useNavigate();
  const { upload, progress, isUploading, error, reset } = useFileUpload();
  const [uploadedId, setUploadedId] = useState<string | null>(null);
  const [isStarting, setIsStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  const handleFileSelect = useCallback(async (file: File) => {
    try {
      const response = await upload(file);
      setUploadedId(response.id);
      setStartError(null);
    } catch {
      // Error is handled by the hook
    }
  }, [upload]);

  const handleStartAnalysis = useCallback(async () => {
    if (!uploadedId) return;

    setIsStarting(true);
    setStartError(null);

    try {
      await startAnalysis(uploadedId);
      navigate(`/analysis/${uploadedId}`);
    } catch (err) {
      setStartError(err instanceof Error ? err.message : 'Failed to start analysis');
    } finally {
      setIsStarting(false);
    }
  }, [uploadedId, navigate]);

  const handleReset = useCallback(() => {
    reset();
    setUploadedId(null);
    setStartError(null);
  }, [reset]);

  return (
    <div className="max-w-3xl mx-auto">
      {/* Header */}
      <div className="text-center mb-8">
        <h1 className="text-2xl sm:text-3xl font-bold text-white mb-2">
          Analyze Network Capture
        </h1>
        <p className="text-slate-400">
          Upload a PCAP file to analyze network traffic, detect security issues, and monitor LAN protocols.
        </p>
      </div>

      {/* Upload zone */}
      <div className="card p-6 mb-6">
        <FileUpload
          onFileSelect={handleFileSelect}
          isUploading={isUploading}
          progress={progress}
          error={error}
          onReset={handleReset}
        />

        {/* Start analysis button */}
        {uploadedId && !isUploading && !error && (
          <div className="mt-6 pt-6 border-t border-slate-700">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="text-center sm:text-left">
                <p className="text-green-400 font-medium">File uploaded successfully!</p>
                <p className="text-sm text-slate-400">Ready to start analysis</p>
              </div>
              <button
                onClick={handleStartAnalysis}
                disabled={isStarting}
                className="btn-primary flex items-center gap-2 w-full sm:w-auto justify-center"
              >
                {isStarting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Starting...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    Start Analysis
                  </>
                )}
              </button>
            </div>

            {startError && (
              <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                <p className="text-red-400 text-sm">{startError}</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Info cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <InfoCard
          title="Security Analysis"
          description="Detect DDoS attacks, DNS anomalies, TLS weaknesses, and ARP conflicts."
        />
        <InfoCard
          title="LAN Protocols"
          description="Monitor VRRP, CDP, LLDP, HSRP, and STP with flapping detection."
        />
        <InfoCard
          title="Performance Metrics"
          description="Analyze TCP handshakes, retransmissions, and packet loss."
        />
        <InfoCard
          title="SD-WAN Detection"
          description="Identify SD-WAN vendors and tunnel protocols."
        />
      </div>

      {/* Tips */}
      <div className="mt-8 p-4 bg-blue-500/10 border border-blue-500/30 rounded-xl">
        <div className="flex gap-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-medium text-blue-400 mb-1">Tips for best results</h3>
            <ul className="text-sm text-slate-400 space-y-1">
              <li>• Capture at least 1 minute of traffic for meaningful analysis</li>
              <li>• Include both directions of traffic when possible</li>
              <li>• For VRRP flapping detection, capture during the suspected issue</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

interface InfoCardProps {
  title: string;
  description: string;
}

function InfoCard({ title, description }: InfoCardProps) {
  return (
    <div className="card p-4">
      <h3 className="font-medium text-white mb-1">{title}</h3>
      <p className="text-sm text-slate-400">{description}</p>
    </div>
  );
}
