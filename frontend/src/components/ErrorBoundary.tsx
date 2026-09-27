import { Component, ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallbackTitle?: string;
  fallbackMessage?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

/**
 * React Error Boundary:
 * Catches rendering errors anywhere in the child component tree,
 * logs error details, and renders a fallback UI instead of a blank white screen.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[Scan ErrorBoundary Caught Rendering Crash]:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  handleGoHome = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex items-center justify-center p-6 my-8">
          <div className="w-full max-w-xl bg-white dark:bg-slate-900 border border-rose-300 dark:border-rose-900/60 rounded-2xl shadow-xl p-6 sm:p-8 space-y-5 animate-fade-in">
            <div className="flex items-center gap-3 text-rose-600 dark:text-rose-400">
              <div className="w-12 h-12 rounded-xl bg-rose-100 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 flex items-center justify-center text-2xl font-bold">
                ⚠️
              </div>
              <div>
                <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                  {this.props.fallbackTitle || 'Analysis Rendering Interrupted'}
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {this.props.fallbackMessage || 'A component error was caught safely without crashing the platform.'}
                </p>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs font-mono space-y-2">
              <div className="text-rose-600 dark:text-rose-400 font-bold break-all">
                {this.state.error?.name || 'Error'}: {this.state.error?.message || 'Unknown runtime rendering error'}
              </div>
              {this.state.errorInfo?.componentStack && (
                <pre className="text-[11px] text-slate-500 dark:text-slate-400 max-h-32 overflow-y-auto whitespace-pre-wrap leading-relaxed">
                  {this.state.errorInfo.componentStack.trim().slice(0, 500)}
                </pre>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                type="button"
                onClick={this.handleReset}
                className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-500 text-white font-bold text-xs shadow-md transition cursor-pointer"
              >
                Reload Page
              </button>
              <button
                type="button"
                onClick={this.handleGoHome}
                className="px-4 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-semibold text-xs border border-slate-200 dark:border-slate-700 transition cursor-pointer"
              >
                Return to Home
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
