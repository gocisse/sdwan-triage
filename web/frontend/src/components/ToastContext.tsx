import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react';
import { AlertTriangle, CheckCircle2, Info, XCircle, X } from 'lucide-react';

// ─── Types ──────────────────────────────────────────────────────────

export type ToastType = 'error' | 'warning' | 'success' | 'info';

export interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number; // ms, 0 = sticky
}

interface ToastContextValue {
  toasts: Toast[];
  addToast: (toast: Omit<Toast, 'id'>) => void;
  removeToast: (id: string) => void;
}

// ─── Context ────────────────────────────────────────────────────────

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}

// ─── Provider ───────────────────────────────────────────────────────

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counterRef = useRef(0);
  const addToastRef = useRef<ToastContextValue['addToast']>(() => {});

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const addToast = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = `toast-${++counterRef.current}`;
    const duration = toast.duration ?? (toast.type === 'error' ? 8000 : 4000);
    setToasts(prev => [...prev.slice(-4), { ...toast, id, duration }]); // max 5 visible
    if (duration > 0) {
      setTimeout(() => removeToast(id), duration);
    }
  }, [removeToast]);

  // Keep a stable ref so the global handler always calls the latest addToast
  addToastRef.current = addToast;

  // Register global API error handler on mount
  useEffect(() => {
    // Lazy import to avoid circular dependency
    import('../api/client').then(({ setGlobalApiErrorHandler }) => {
      setGlobalApiErrorHandler(({ title, message }) => {
        addToastRef.current({ type: 'error', title, message });
      });
    });
    return () => {
      import('../api/client').then(({ setGlobalApiErrorHandler }) => {
        setGlobalApiErrorHandler(null);
      });
    };
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, addToast, removeToast }}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={removeToast} />
    </ToastContext.Provider>
  );
}

// ─── Toast Container ────────────────────────────────────────────────

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: string) => void }) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-[9999] flex flex-col gap-2 max-w-sm">
      {toasts.map(toast => (
        <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
      ))}
    </div>
  );
}

// ─── Toast Item ─────────────────────────────────────────────────────

const iconMap: Record<ToastType, React.ReactNode> = {
  error:   <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />,
  warning: <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0" />,
  success: <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />,
  info:    <Info className="w-4 h-4 text-blue-400 flex-shrink-0" />,
};

const bgMap: Record<ToastType, string> = {
  error:   'bg-red-950/90 border-red-500/40',
  warning: 'bg-yellow-950/90 border-yellow-500/40',
  success: 'bg-green-950/90 border-green-500/40',
  info:    'bg-blue-950/90 border-blue-500/40',
};

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  return (
    <div
      className={`flex items-start gap-2 px-4 py-3 rounded-lg border shadow-lg backdrop-blur-sm animate-in slide-in-from-right ${bgMap[toast.type]}`}
      role="alert"
    >
      {iconMap[toast.type]}
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-white">{toast.title}</div>
        {toast.message && (
          <div className="text-xs text-slate-400 mt-0.5 line-clamp-2">{toast.message}</div>
        )}
      </div>
      <button
        onClick={() => onDismiss(toast.id)}
        className="flex-shrink-0 p-0.5 rounded hover:bg-white/10 transition-colors"
      >
        <X className="w-3.5 h-3.5 text-slate-500" />
      </button>
    </div>
  );
}
