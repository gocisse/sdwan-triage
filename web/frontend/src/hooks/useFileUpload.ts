// Custom hook for file upload with progress tracking

import { useState, useCallback } from 'react';
import { uploadFile, ApiError } from '../api/client';
import type { UploadResponse } from '../types';

interface UseFileUploadReturn {
  upload: (file: File) => Promise<UploadResponse>;
  progress: number;
  isUploading: boolean;
  error: string | null;
  reset: () => void;
}

// Allowed file extensions
const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];
const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB

export function useFileUpload(): UseFileUploadReturn {
  const [progress, setProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validateFile = useCallback((file: File): string | null => {
    // Check file extension
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return `Invalid file type. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`;
    }

    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      return `File too large. Maximum size: 500MB`;
    }

    // Check if file is empty
    if (file.size === 0) {
      return 'File is empty';
    }

    return null;
  }, []);

  const upload = useCallback(async (file: File): Promise<UploadResponse> => {
    // Validate file first
    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      throw new Error(validationError);
    }

    setIsUploading(true);
    setProgress(0);
    setError(null);

    try {
      const response = await uploadFile(file, (uploadProgress) => {
        setProgress(uploadProgress);
      });
      
      setProgress(100);
      return response;
    } catch (err) {
      const message = err instanceof ApiError 
        ? err.message 
        : 'Upload failed. Please try again.';
      setError(message);
      throw err;
    } finally {
      setIsUploading(false);
    }
  }, [validateFile]);

  const reset = useCallback(() => {
    setProgress(0);
    setIsUploading(false);
    setError(null);
  }, []);

  return {
    upload,
    progress,
    isUploading,
    error,
    reset,
  };
}
