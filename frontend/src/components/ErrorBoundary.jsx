import React from 'react';
import { ErrorBoundary } from 'react-error-boundary';
import { AlertTriangle, RefreshCw } from 'lucide-react';

const ErrorFallback = ({ error, resetErrorBoundary }) => {
    return (
        <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-slate-900 text-white">
            <div className="w-16 h-16 bg-red-500/20 rounded-2xl flex items-center justify-center mb-6 ring-4 ring-red-500/10">
                <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>

            <h2 className="text-2xl font-bold mb-2">Something went wrong</h2>
            <p className="text-gray-400 text-center mb-6 max-w-sm">
                The application encountered an unexpected error.
            </p>

            <div className="bg-slate-800 p-4 rounded-xl border border-slate-700 w-full max-w-md mb-6 overflow-hidden">
                <p className="font-mono text-xs text-red-300 break-words">
                    {error.message}
                </p>
            </div>

            <button
                onClick={resetErrorBoundary}
                className="btn-primary py-3 px-6 flex items-center gap-2"
            >
                <RefreshCw size={18} /> Try Again
            </button>
        </div>
    );
};

export const AppErrorBoundary = ({ children }) => {
    return (
        <ErrorBoundary
            FallbackComponent={ErrorFallback}
            onReset={() => {
                // Reset the state of your app so the error doesn't happen again
                window.location.reload();
            }}
        >
            {children}
        </ErrorBoundary>
    );
};
