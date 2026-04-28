import { useState } from 'react';
import KeyLab from './components/KeyLab';
import InteractiveDemos from './components/InteractiveDemos';

function App() {
  const [activeTab, setActiveTab] = useState<'lab' | 'interactive'>('lab');

  return (
    <div className="app-container">
      <header className="panel" style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <h1>RSA Learning Lab</h1>
        <p>
          Master the fundamentals of RSA through direct experimentation and interactive side-by-side simulations.
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
          className={`tab ${activeTab === 'interactive' ? 'active' : ''}`}
          onClick={() => setActiveTab('interactive')}
        >
          Interactive Demos
        </div>
      </div>

      <main>
        {activeTab === 'lab' ? <KeyLab /> : <InteractiveDemos />}
      </main>
    </div>
  );
}

export default App;
