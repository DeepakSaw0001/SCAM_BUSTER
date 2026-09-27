import React from 'react';
import { useTheme } from '../context/ThemeContext';

export const ThemeToggle: React.FC<{ className?: string }> = ({ className = '' }) => {
  const { resolvedTheme, toggleTheme } = useTheme();
  const isDark = resolvedTheme === 'dark';

  return (
    <button
      id="theme-toggle-btn"
      data-testid="theme-toggle-btn"
      onClick={toggleTheme}
      type="button"
      className={`relative p-2 rounded-xl transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-brand-500/50 ${
        isDark
          ? 'bg-slate-800/80 text-amber-400 hover:bg-slate-800 hover:text-amber-300 border border-slate-700/60 shadow-inner'
          : 'bg-slate-100 text-indigo-600 hover:bg-slate-200/80 border border-slate-300 shadow-sm'
      } ${className}`}
      title={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
      aria-label={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
    >
      <div className="w-5 h-5 flex items-center justify-center transition-transform duration-500 transform hover:scale-110">
        {isDark ? (
          // Sun Icon with glowing aura
          <svg
            className="w-4 h-4 transition-transform duration-500 rotate-0 hover:rotate-45"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
            />
          </svg>
        ) : (
          // Moon Icon
          <svg
            className="w-4 h-4 transition-transform duration-500 -rotate-12 hover:rotate-0"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
            />
          </svg>
        )}
      </div>
    </button>
  );
};
