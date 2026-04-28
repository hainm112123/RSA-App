import { useState } from 'react';
import KeyLab from './components/KeyLab';
import HybridDemo from './components/HybridDemo';

function App() {
  const [activeTab, setActiveTab] = useState<'lab' | 'hybrid'>('lab');

  return (
    <div className="app-container">
      <header className="panel" style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <h1>RSA Cryptography</h1>
        <p>
          Learn and present RSA cryptography by experimenting directly, or by simulating a secure communication flow with up to 8192-bit key support and number-based key visualization.
        </p>
      </header>

      <div className="tabs">
        <div 
          className={`tab ${activeTab === 'lab' ? 'active' : ''}`}
          onClick={() => setActiveTab('lab')}
        >
          RSA Lab
        </div>
        <div 
          className={`tab ${activeTab === 'hybrid' ? 'active' : ''}`}
          onClick={() => setActiveTab('hybrid')}
        >
          Secure Transfer Demo
        </div>
      </div>

      <main>
        {activeTab === 'lab' ? <KeyLab /> : <HybridDemo />}
      </main>
    </div>
  );
}

export default App;
