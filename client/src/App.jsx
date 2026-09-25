import { Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Analyze from './pages/Analyze';
import History from './pages/History';
import About from './pages/About';

export default function App() {
  return (
    <>
      <Navbar />
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analyze" element={<Analyze />} />
          <Route path="/history" element={<History />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={
            <div style={{ textAlign: 'center', padding: '60px 20px' }}>
              <h1 style={{ fontSize: '3rem', fontWeight: 800, marginBottom: '8px' }}>404</h1>
              <p style={{ color: 'var(--color-text-secondary)' }}>Page not found</p>
            </div>
          } />
        </Routes>
      </main>
    </>
  );
}
