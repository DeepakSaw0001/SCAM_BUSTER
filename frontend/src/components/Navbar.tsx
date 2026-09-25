import React from 'react';
import { NavLink } from 'react-router-dom';
import { BackendStatus } from './BackendStatus';

export const Navbar: React.FC = () => {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
      isActive
        ? 'text-brand-500 bg-brand-500/10'
        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
    }`;

  return (
    <header className="border-b border-slate-800 bg-dark-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <NavLink to="/" className="flex items-center gap-2.5 font-bold text-lg text-white">
            <span className="w-8 h-8 rounded-lg bg-gradient-to-tr from-brand-600 to-emerald-400 flex items-center justify-center text-dark-950 text-base font-black shadow-lg shadow-brand-500/20">
              🛡️
            </span>
            <span>Scam<span className="text-brand-500">Buster</span></span>
          </NavLink>

          <nav className="hidden md:flex items-center gap-1">
            <NavLink to="/" className={linkClass}>Home</NavLink>
            <NavLink to="/scan" className={linkClass}>Scan</NavLink>
            <NavLink to="/dashboard" className={linkClass}>Dashboard</NavLink>
            <NavLink to="/history" className={linkClass}>History</NavLink>
            <NavLink to="/reports" className={linkClass}>Reports</NavLink>
            <NavLink to="/settings" className={linkClass}>Settings</NavLink>
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <BackendStatus />
        </div>
      </div>
    </header>
  );
};
