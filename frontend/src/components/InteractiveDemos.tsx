import React, { useState, useEffect } from 'react';

const API_BASE = 'http://127.0.0.1:5000/api';

export default function InteractiveDemos() {
  const [activeTab, setActiveTab] = useState('messaging');
  
  // Common state
  const [aliceKey, setAliceKey] = useState<any>(null);
  const [bobKey, setBobKey] = useState<any>(null);
  const [loadingKeys, setLoadingKeys] = useState(false);
  
  // Secure Messaging State
  const [aliceMessage, setAliceMessage] = useState('Hello Bob! This is a top-secret RSA message.');
  const [encryptedMessage, setEncryptedMessage] = useState<any>(null);
  const [bobDecrypted, setBobDecrypted] = useState<string | null>(null);
  const [messagingStep, setMessagingStep] = useState(0); // 0: Start, 1: Encrypted, 2: In-Transit, 3: Decrypted
  const [loadingEncrypt, setLoadingEncrypt] = useState(false);
  const [loadingDecrypt, setLoadingDecrypt] = useState(false);

  // Digital Notary State
  const [notaryDoc, setNotaryDoc] = useState('I, Alice, hereby certify that I have received 500 units of currency from Bob.');
  const [signature, setSignature] = useState<any>(null);
  const [verifierResult, setVerifierResult] = useState<any>(null);
  const [isTampered, setIsTampered] = useState(false);
  const [loadingSign, setLoadingSign] = useState(false);
  const [loadingVerify, setLoadingVerify] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    initDemoKeys();
  }, []);

  const initDemoKeys = async () => {
    setLoadingKeys(true);
    setError(null);
    try {
      const [resA, resB] = await Promise.all([
        fetch(`${API_BASE}/generate-keys`, { 
          method: 'POST', 
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ bits: 2048, e_type: 'standard' }) 
        }),
        fetch(`${API_BASE}/generate-keys`, { 
          method: 'POST', 
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ bits: 2048, e_type: 'standard' }) 
        })
      ]);
      const dataA = await resA.json();
      const dataB = await resB.json();
      if (dataA.success) setAliceKey(dataA.data);
      if (dataB.success) setBobKey(dataB.data);
    } catch (e) {
      console.error("Failed to init keys", e);
    } finally {
      setLoadingKeys(false);
    }
  };

  const handleAliceEncrypt = async () => {
    if (!bobKey) return;
    setLoadingEncrypt(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/rsa-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'encrypt',
          display_mode: 'encoded',
          payload: aliceMessage,
          public_key: bobKey.public_key_pem
        })
      });
      const data = await res.json();
      if (data.success) {
        setEncryptedMessage(data.data);
        setMessagingStep(1);
      } else {
        setError(data.error);
      }
    } catch (e: any) { 
      setError(e.message);
      console.error(e); 
    }
    finally { setLoadingEncrypt(false); }
  };

  const handleBobDecrypt = async () => {
    if (!bobKey || !encryptedMessage) return;
    setLoadingDecrypt(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/rsa-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'decrypt',
          display_mode: 'encoded',
          ciphertext_b64: encryptedMessage.ciphertext_b64,
          private_key: bobKey.private_key_pem
        })
      });
      const data = await res.json();
      if (data.success) {
        setBobDecrypted(data.data.plaintext);
        setMessagingStep(3);
      } else {
        setError(data.error);
        setBobDecrypted(null);
      }
    } catch (e: any) { 
      setError(e.message);
      console.error(e); 
      setBobDecrypted(null);
    }
    finally { setLoadingDecrypt(false); }
  };

  const handleNotarySign = async () => {
    if (!aliceKey) return;
    setLoadingSign(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/rsa-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'sign',
          display_mode: 'encoded',
          payload: notaryDoc,
          private_key: aliceKey.private_key_pem
        })
      });
      const data = await res.json();
      if (data.success) {
        setSignature(data.data);
        setVerifierResult(null);
        setIsTampered(false);
      } else {
        setError(data.error);
      }
    } catch (e: any) { 
      setError(e.message);
      console.error(e); 
    }
    finally { setLoadingSign(false); }
  };

  const handleNotaryVerify = async () => {
    if (!aliceKey || !signature) return;
    setLoadingVerify(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/rsa-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'verify',
          display_mode: 'encoded',
          payload: notaryDoc,
          signature_b64: signature.signature_b64,
          public_key: aliceKey.public_key_pem
        })
      });
      const data = await res.json();
      if (data.success) {
        setVerifierResult(data.data);
      } else {
        setError(data.error);
        setVerifierResult(null);
      }
    } catch (e: any) { 
      setError(e.message);
      console.error(e); 
      setVerifierResult(null);
    }
    finally { setLoadingVerify(false); }
  };

  const tamperDoc = () => {
    setNotaryDoc(prev => prev + " [TAMPERED]");
    setIsTampered(true);
    setVerifierResult(null);
  };

  const resetNotary = () => {
    setSignature(null);
    setVerifierResult(null);
    setIsTampered(false);
    setNotaryDoc('I, Alice, hereby certify that I have received 500 units of currency from Bob.');
  };

  const resetMessaging = () => {
    setMessagingStep(0);
    setEncryptedMessage(null);
    setBobDecrypted(null);
  };

  return (
    <div className="stack">
      <div className="flex" style={{ gap: '1rem', marginBottom: '2rem', background: 'rgba(255,255,255,0.05)', padding: '0.5rem', borderRadius: '12px', width: 'fit-content' }}>
        <button 
          className="btn"
          style={{ 
            background: activeTab === 'messaging' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'messaging' ? '#fff' : 'var(--text-secondary)',
            boxShadow: activeTab === 'messaging' ? '0 4px 12px rgba(99, 102, 241, 0.3)' : 'none'
          }}
          onClick={() => setActiveTab('messaging')}
        >
          Secure Messaging
        </button>
        <button 
          className="btn"
          style={{ 
            background: activeTab === 'notary' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'notary' ? '#fff' : 'var(--text-secondary)',
            boxShadow: activeTab === 'notary' ? '0 4px 12px rgba(99, 102, 241, 0.3)' : 'none'
          }}
          onClick={() => setActiveTab('notary')}
        >
          Digital Notary
        </button>
      </div>

      {loadingKeys ? (
        <article className="panel" style={{ textAlign: 'center', padding: '4rem' }}>
          <span className="loader loader-large"></span>
          <p style={{ marginTop: '1.5rem', color: 'var(--text-primary)', fontSize: '1.1rem' }}>Initializing identities (Alice & Bob)...</p>
          <p style={{ fontSize: '0.9rem' }}>Retrieving 2048-bit keys from the background pool.</p>
        </article>
      ) : (
        <>
          {error && <div className="status error" style={{ marginBottom: '1.5rem' }}>{error}</div>}
          {activeTab === 'messaging' && (
            <div className="grid grid-cols-2">
              <div className="stack">
                <article className="panel" style={{ borderTop: '4px solid var(--accent)' }}>
                  <div className="flex-between" style={{ marginBottom: '1rem' }}>
                    <h3 style={{ margin: 0 }}>Alice's Terminal</h3>
                    <span className="badge" style={{ margin: 0, background: 'rgba(99, 102, 241, 0.2)', color: '#a5b4fc' }}>Sender</span>
                  </div>
                  <p style={{ fontSize: '0.9rem' }}>Alice encrypts her secret using <strong>Bob's Public Key</strong>.</p>
                  
                  <div className="input-group">
                    <label>Secret Message</label>
                    <textarea 
                      value={aliceMessage} 
                      onChange={e => setAliceMessage(e.target.value)}
                      disabled={messagingStep > 0}
                      style={{ height: '100px' }}
                    />
                  </div>

                  <div className="flex" style={{ gap: '0.75rem' }}>
                    <button 
                      className="btn" 
                      onClick={handleAliceEncrypt}
                      disabled={messagingStep > 0 || loadingEncrypt || !bobKey}
                      style={{ flex: 1 }}
                    >
                      {loadingEncrypt ? <span className="loader"></span> : null}
                      {messagingStep >= 1 ? 'Encrypted ✓' : 'Encrypt with Bob\'s Key'}
                    </button>
                    {messagingStep === 1 && (
                      <button className="btn btn-outline" style={{ border: '1px solid var(--accent)', background: 'transparent' }} onClick={() => setMessagingStep(2)}>
                        Send Message ➔
                      </button>
                    )}
                  </div>

                  {encryptedMessage?.ciphertext_b64 && (
                    <div style={{ marginTop: '1.5rem' }}>
                      <label style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Ciphertext Result</label>
                      <textarea 
                        readOnly 
                        value={encryptedMessage.ciphertext_b64}
                        style={{ 
                          height: '80px',
                          fontSize: '0.75rem', 
                          fontFamily: 'monospace',
                          color: 'var(--accent)',
                          background: 'rgba(0,0,0,0.3)'
                        }}
                      />
                    </div>
                  )}
                </article>

                {messagingStep === 2 && (
                  <div className="panel" style={{ textAlign: 'center', background: 'rgba(99, 102, 241, 0.05)', border: '1px dashed var(--accent)', padding: '1rem' }}>
                    <div className="status" style={{ margin: 0, padding: 0, color: 'var(--accent)' }}>
                      📡 Ciphertext is currently traveling across the insecure internet...
                    </div>
                  </div>
                )}
              </div>

              <div className="stack">
                <article className="panel" style={{ borderTop: '4px solid var(--success)' }}>
                  <div className="flex-between" style={{ marginBottom: '1rem' }}>
                    <h3 style={{ margin: 0 }}>Bob's Terminal</h3>
                    <span className="badge" style={{ margin: 0, background: 'rgba(16, 185, 129, 0.2)', color: '#6ee7b7' }}>Receiver</span>
                  </div>
                  <p style={{ fontSize: '0.9rem' }}>Bob receives the scrambled data. Only his <strong>Private Key</strong> can decrypt it.</p>
                  
                  <div className="input-group">
                    <label>Incoming Data</label>
                    <textarea 
                      readOnly 
                      value={messagingStep >= 2 && encryptedMessage?.ciphertext_b64 ? encryptedMessage.ciphertext_b64 : 'Waiting for incoming transmission...'}
                      style={{ 
                        height: '100px', 
                        opacity: messagingStep >= 2 ? 1 : 0.4,
                        background: messagingStep >= 2 ? 'rgba(0,0,0,0.3)' : 'rgba(15, 23, 42, 0.8)'
                      }}
                    />
                  </div>

                  <button 
                    className="btn" 
                    onClick={handleBobDecrypt}
                    disabled={messagingStep < 2 || messagingStep === 3 || loadingDecrypt || !bobKey}
                    style={{ width: '100%', background: 'var(--success)' }}
                  >
                    {loadingDecrypt ? <span className="loader"></span> : null}
                    Decrypt with Private Key
                  </button>

                  {bobDecrypted && (
                    <div className="status ok" style={{ marginTop: '1.5rem' }}>
                      <strong style={{ fontSize: '0.8rem', display: 'block', marginBottom: '0.5rem' }}>DECRYPTED CONTENT:</strong>
                      <div style={{ fontSize: '1.1rem', fontWeight: 600 }}>{bobDecrypted}</div>
                    </div>
                  )}

                  {messagingStep === 3 && (
                    <button className="btn btn-outline" onClick={resetMessaging} style={{ marginTop: '1rem', width: '100%', border: '1px solid rgba(255,255,255,0.2)' }}>
                      Clear & Reset Simulation
                    </button>
                  )}
                </article>
              </div>
            </div>
          )}

          {activeTab === 'notary' && (
            <div className="grid grid-cols-2">
              <article className="panel" style={{ borderTop: '4px solid var(--accent)' }}>
                <div className="flex-between" style={{ marginBottom: '1rem' }}>
                  <h3 style={{ margin: 0 }}>Document Source</h3>
                  <span className="badge" style={{ margin: 0, background: 'rgba(99, 102, 241, 0.2)', color: '#a5b4fc' }}>Alice (Signer)</span>
                </div>
                <p style={{ fontSize: '0.9rem' }}>Alice signs the hash of this document using her <strong>Private Key</strong>.</p>
                
                <div className="input-group">
                  <label>Document Text</label>
                  <textarea 
                    value={notaryDoc} 
                    onChange={e => {
                      setNotaryDoc(e.target.value);
                      if (signature) setIsTampered(true);
                    }}
                    style={{ height: '140px' }}
                  />
                </div>

                <div className="flex" style={{ gap: '0.75rem' }}>
                  <button className="btn" onClick={handleNotarySign} disabled={loadingSign || !aliceKey} style={{ flex: 1 }}>
                    {loadingSign ? <span className="loader"></span> : null}
                    {signature ? 'Update Signature' : 'Sign Document'}
                  </button>
                  {signature && (
                    <button 
                      className="btn btn-outline" 
                      style={{ color: 'var(--error)', border: '1px solid var(--error)' }} 
                      onClick={tamperDoc}
                    >
                      Simulate Tamper!
                    </button>
                  )}
                </div>

                {signature?.signature_b64 && (
                  <div style={{ marginTop: '1.5rem' }}>
                    <label style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>Digital Signature (RSA-PSS)</label>
                    <textarea 
                      readOnly 
                      value={signature.signature_b64}
                      style={{ 
                        height: '80px',
                        fontSize: '0.7rem', 
                        fontFamily: 'monospace',
                        opacity: 0.8,
                        background: 'rgba(0,0,0,0.3)'
                      }}
                    />
                  </div>
                )}
              </article>

              <article className="panel" style={{ borderTop: '4px solid var(--success)' }}>
                <div className="flex-between" style={{ marginBottom: '1rem' }}>
                  <h3 style={{ margin: 0 }}>Verifier Terminal</h3>
                  <span className="badge" style={{ margin: 0, background: 'rgba(16, 185, 129, 0.2)', color: '#6ee7b7' }}>Public Access</span>
                </div>
                <p style={{ fontSize: '0.9rem' }}>Anyone can use Alice's <strong>Public Key</strong> to verify the document's integrity.</p>
                
                <div className="input-group">
                  <label>Document to Verify</label>
                  <div style={{ 
                    padding: '1.25rem', 
                    background: 'rgba(255,255,255,0.03)', 
                    borderRadius: '8px', 
                    fontSize: '0.9rem',
                    lineHeight: 1.6,
                    border: isTampered ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(255,255,255,0.05)',
                    color: isTampered ? '#fca5a5' : 'inherit'
                  }}>
                    {notaryDoc}
                    {isTampered && <div style={{ fontSize: '0.7rem', color: 'var(--error)', marginTop: '0.5rem', fontWeight: 700 }}>⚠️ CONTENT MODIFIED AFTER SIGNING</div>}
                  </div>
                </div>

                <button 
                  className="btn" 
                  onClick={handleNotaryVerify}
                  disabled={!signature?.signature_b64 || loadingVerify || !aliceKey}
                  style={{ width: '100%', background: 'var(--success)' }}
                >
                  {loadingVerify ? <span className="loader"></span> : null}
                  Verify Integrity
                </button>

                {verifierResult && typeof verifierResult === 'object' && (
                  <div className={`status ${verifierResult.verified ? 'ok' : 'error'}`} style={{ marginTop: '1.5rem', textAlign: 'center' }}>
                    {verifierResult.verified ? (
                      <div>
                        <div style={{ fontSize: '1.25rem', marginBottom: '0.25rem' }}>✅ AUTHENTIC</div>
                        <div style={{ fontSize: '0.85rem', opacity: 0.9 }}>Integrity verified. Document is exactly as Alice signed it.</div>
                      </div>
                    ) : (
                      <div>
                        <div style={{ fontSize: '1.25rem', marginBottom: '0.25rem' }}>❌ TAMPERED</div>
                        <div style={{ fontSize: '0.85rem', opacity: 0.9 }}>Verification failed! The document has been modified.</div>
                      </div>
                    )}
                  </div>
                )}

                {signature && (
                  <button className="btn btn-outline" onClick={resetNotary} style={{ marginTop: '1rem', width: '100%', border: '1px solid rgba(255,255,255,0.1)' }}>
                    Reset Document
                  </button>
                )}
              </article>
            </div>
          )}
        </>
      )}
    </div>
  );
}
