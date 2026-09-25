import { NavLink, Link } from 'react-router-dom';
import { useTheme } from '../hooks/useTheme';
import { useState } from 'react';

export default function Navbar() {
  const { theme, toggleTheme } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <nav className="nav">
      <div className="nav__inner">
        <Link to="/" className="nav__brand">
          <img src="/shield.svg" alt="ScamBuster" className="nav__brand-icon" />
          ScamBuster
        </Link>

        <button
          className="nav__hamburger"
          onClick={() => setMenuOpen(!menuOpen)}
          aria-label="Toggle menu"
        >
          {menuOpen ? '✕' : '☰'}
        </button>

        <div className={`nav__links ${menuOpen ? 'nav__links--open' : ''}`}>
          <NavLink
            to="/"
            className={({ isActive }) => `nav__link ${isActive ? 'nav__link--active' : ''}`}
            onClick={() => setMenuOpen(false)}
            end
          >
            Dashboard
          </NavLink>
          <NavLink
            to="/analyze"
            className={({ isActive }) => `nav__link ${isActive ? 'nav__link--active' : ''}`}
            onClick={() => setMenuOpen(false)}
          >
            Analyze
          </NavLink>
          <NavLink
            to="/history"
            className={({ isActive }) => `nav__link ${isActive ? 'nav__link--active' : ''}`}
            onClick={() => setMenuOpen(false)}
          >
            History
          </NavLink>
          <NavLink
            to="/about"
            className={({ isActive }) => `nav__link ${isActive ? 'nav__link--active' : ''}`}
            onClick={() => setMenuOpen(false)}
          >
            About
          </NavLink>
        </div>

        <div className="nav__actions">
          <button
            className="theme-toggle"
            onClick={toggleTheme}
            aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
            title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
          >
            {theme === 'light' ? '🌙' : '☀️'}
          </button>
        </div>
      </div>
    </nav>
  );
}
