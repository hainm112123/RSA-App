import React, { useState } from 'react';

const API_BASE = 'http://127.0.0.1:5000/api';
const BIT_OPTIONS = [1024, 1536, 2048, 3072, 4096, 8192];

export default function KeyLab() {
  const [bits, setBits] = useState(2048);
  const [eType, setEType] = useState('standard');
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [keyResult, setKeyResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Playground state
  const [mode, setMode] = useState('encrypt');
  const [displayMode, setDisplayMode] = useState('encoded');
  
  const [payload, setPayload] = useState('');
  
  // Encoded fields
  const [publicKey, setPublicKey] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [ciphertextB64, setCiphertextB64] = useState('');
  const [signatureB64, setSignatureB64] = useState('');
  
  // Numerical fields
  const [publicKeyN, setPublicKeyN] = useState('');
  const [publicKeyE, setPublicKeyE] = useState('');
  const [privateKeyN, setPrivateKeyN] = useState('');
  const [privateKeyD, setPrivateKeyD] = useState('');
  const [ciphertextNum, setCiphertextNum] = useState('');
  const [signatureNum, setSignatureNum] = useState('');

  const [actionLoading, setActionLoading] = useState(false);
  const [actionResult, setActionResult] = useState<any>(null);

  const generateKeys = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoadingKeys(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/generate-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bits, e_type: eType })
      });
      const data = await res.json();
      if (data.success) {
        setKeyResult(data.data);
        
        // Auto-fill inputs for convenience
        setPublicKey(data.data.public_key_pem);
        setPrivateKey(data.data.private_key_pem);
        setPublicKeyN(data.data.public_key_n);
        setPublicKeyE(data.data.public_key_e);
        setPrivateKeyN(data.data.private_key_n);
        setPrivateKeyD(data.data.private_key_d);
      } else {
        setError(data.error);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingKeys(false);
    }
  };

  const runAction = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/rsa-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          display_mode: displayMode,
          payload,
          public_key: publicKey,
          private_key: privateKey,
          ciphertext_b64: ciphertextB64,
          signature_b64: signatureB64,
          public_key_n: publicKeyN,
          public_key_e: publicKeyE,
          private_key_n: privateKeyN,
          private_key_d: privateKeyD,
          ciphertext_num: ciphertextNum,
          signature_num: signatureNum
        })
      });
      const data = await res.json();
      if (data.success) {
        setActionResult(data.data);
      } else {
        setError(data.error);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-2">
      <div className="stack">
        <article className="panel">
          <h2>1. Generate RSA Keys</h2>
          <p>Generate keys using Miller-Rabin primality testing. You can create keys up to 8192 bits.</p>
          
          <form onSubmit={generateKeys}>
            <div className="grid grid-cols-2" style={{ gap: '1rem', marginBottom: '1rem' }}>
              <div className="input-group" style={{ marginBottom: 0 }}>
                <label>Key size</label>
                <select value={bits} onChange={e => setBits(Number(e.target.value))} disabled={loadingKeys}>
                  {BIT_OPTIONS.map(b => (
                    <option key={b} value={b}>{b} bits</option>
                  ))}
                </select>
              </div>
              <div className="input-group" style={{ marginBottom: 0 }}>
                <label>Public Exponent (e)</label>
                <select value={eType} onChange={e => setEType(e.target.value)} disabled={loadingKeys}>
                  <option value="standard">Standard (65537)</option>
                  <option value="random">Random Large</option>
                </select>
              </div>
            </div>
            <button className="btn" type="submit" disabled={loadingKeys}>
              {loadingKeys ? <><span className="loader"></span> Generating...</> : 'Generate keys'}
            </button>
          </form>

          {keyResult && !loadingKeys && (
            <div style={{ marginTop: '1.5rem' }}>
              <div className="status ok">
                {keyResult.pooled ? 'Key retrieved instantly from background pool.' : `Generation completed in ${keyResult.elapsed.toFixed(3)}s.`}
              </div>
              
              <div className="input-group">
                <label>Public Key (Number - Modulus n)</label>
                <textarea readOnly value={keyResult.public_key_n} style={{ height: '80px' }}></textarea>
              </div>
              <div className="input-group">
                <label>Public Key Exponent (e)</label>
                <textarea readOnly value={keyResult.public_key_e} style={{ height: '80px' }}></textarea>
              </div>
              <div className="input-group">
                <label>Private Key Exponent (d)</label>
                <textarea readOnly value={keyResult.private_key_d} style={{ height: '80px' }}></textarea>
              </div>

              <div className="input-group">
                <label>Public Key (PEM)</label>
                <textarea readOnly value={keyResult.public_key_pem}></textarea>
              </div>
              <div className="input-group">
                <label>Private Key (PEM)</label>
                <textarea readOnly value={keyResult.private_key_pem}></textarea>
              </div>
            </div>
          )}
        </article>

        {error && <div className="status error">{error}</div>}
      </div>

      <div>
        <article className="panel">
          <h2>2. RSA Playground</h2>
          <p>Choose an action to encrypt, decrypt, sign, or verify. Input data is UTF-8 text.</p>
          
          <form onSubmit={runAction}>
            <div className="grid grid-cols-2" style={{ gap: '1rem', marginBottom: '1rem' }}>
              <div className="input-group" style={{ marginBottom: 0 }}>
                <label>Action</label>
                <select value={mode} onChange={e => setMode(e.target.value)}>
                  <option value="encrypt">Encrypt</option>
                  <option value="decrypt">Decrypt</option>
                  <option value="sign">Sign</option>
                  <option value="verify">Verify signature</option>
                </select>
              </div>
              <div className="input-group" style={{ marginBottom: 0 }}>
                <label>Display Format</label>
                <select value={displayMode} onChange={e => setDisplayMode(e.target.value)}>
                  <option value="encoded">Encoded (PEM / Base64)</option>
                  <option value="numerical">Numerical (Base-10)</option>
                </select>
              </div>
            </div>

            {['encrypt', 'sign', 'verify'].includes(mode) && (
              <div className="input-group">
                <label>Input message</label>
                <textarea 
                  placeholder="Enter content..." 
                  value={payload} 
                  onChange={e => setPayload(e.target.value)} 
                />
              </div>
            )}

            {/* PUBLIC KEY */}
            {['encrypt', 'verify'].includes(mode) && displayMode === 'encoded' && (
              <div className="input-group">
                <label>Public Key (PEM)</label>
                <textarea 
                  value={publicKey} 
                  onChange={e => setPublicKey(e.target.value)} 
                  placeholder="Paste public key here"
                />
              </div>
            )}
            {['encrypt', 'verify'].includes(mode) && displayMode === 'numerical' && (
              <>
                <div className="input-group">
                  <label>Public Key Modulus (n)</label>
                  <textarea 
                    value={publicKeyN} 
                    onChange={e => setPublicKeyN(e.target.value)} 
                    placeholder="Paste modulus n here"
                  />
                </div>
                <div className="input-group">
                  <label>Public Key Exponent (e)</label>
                  <input 
                    type="text"
                    value={publicKeyE} 
                    onChange={e => setPublicKeyE(e.target.value)} 
                    placeholder="Paste exponent e here"
                  />
                </div>
              </>
            )}

            {/* PRIVATE KEY */}
            {['decrypt', 'sign'].includes(mode) && displayMode === 'encoded' && (
              <div className="input-group">
                <label>Private Key (PEM)</label>
                <textarea 
                  value={privateKey} 
                  onChange={e => setPrivateKey(e.target.value)} 
                  placeholder="Paste private key here"
                />
              </div>
            )}
            {['decrypt', 'sign'].includes(mode) && displayMode === 'numerical' && (
              <>
                <div className="input-group">
                  <label>Private Key Modulus (n)</label>
                  <textarea 
                    value={privateKeyN} 
                    onChange={e => setPrivateKeyN(e.target.value)} 
                    placeholder="Paste modulus n here"
                  />
                </div>
                <div className="input-group">
                  <label>Private Key Exponent (d)</label>
                  <textarea 
                    value={privateKeyD} 
                    onChange={e => setPrivateKeyD(e.target.value)} 
                    placeholder="Paste private exponent d here"
                  />
                </div>
              </>
            )}

            {/* CIPHERTEXT / SIGNATURE INPUTS */}
            {['decrypt'].includes(mode) && displayMode === 'encoded' && (
              <div className="input-group">
                <label>Ciphertext Base64</label>
                <textarea 
                  value={ciphertextB64} 
                  onChange={e => setCiphertextB64(e.target.value)} 
                  placeholder="Required for decryption"
                />
              </div>
            )}
            {['decrypt'].includes(mode) && displayMode === 'numerical' && (
              <div className="input-group">
                <label>Ciphertext Number</label>
                <textarea 
                  value={ciphertextNum} 
                  onChange={e => setCiphertextNum(e.target.value)} 
                  placeholder="Paste large number here"
                />
              </div>
            )}

            {['verify'].includes(mode) && displayMode === 'encoded' && (
              <div className="input-group">
                <label>Signature Base64</label>
                <textarea 
                  value={signatureB64} 
                  onChange={e => setSignatureB64(e.target.value)} 
                  placeholder="Required for signature verification"
                />
              </div>
            )}
            {['verify'].includes(mode) && displayMode === 'numerical' && (
              <div className="input-group">
                <label>Signature Number</label>
                <textarea 
                  value={signatureNum} 
                  onChange={e => setSignatureNum(e.target.value)} 
                  placeholder="Paste large number here"
                />
              </div>
            )}

            <button className="btn" type="submit" disabled={actionLoading}>
              {actionLoading ? <><span className="loader"></span> Processing...</> : 'Run action'}
            </button>
          </form>

          {actionResult && !actionLoading && (
            <div style={{ marginTop: '1.5rem' }}>
              <div className="status ok">Completed in {actionResult.elapsed.toFixed(4)}s.</div>
              {actionResult.mode === 'encrypt' && (
                <div className="input-group">
                  <label>{displayMode === 'encoded' ? 'Ciphertext Base64' : 'Ciphertext Number'}</label>
                  <pre>{displayMode === 'encoded' ? actionResult.ciphertext_b64 : actionResult.ciphertext_num}</pre>
                </div>
              )}
              {actionResult.mode === 'decrypt' && (
                <div className="input-group">
                  <label>Plaintext</label>
                  <pre>{actionResult.plaintext}</pre>
                </div>
              )}
              {actionResult.mode === 'sign' && (
                <div className="input-group">
                  <label>{displayMode === 'encoded' ? 'Signature Base64' : 'Signature Number'}</label>
                  <pre>{displayMode === 'encoded' ? actionResult.signature_b64 : actionResult.signature_num}</pre>
                </div>
              )}
              {actionResult.mode === 'verify' && (
                <div className={`status ${actionResult.verified ? 'ok' : 'error'}`}>
                  Verification result: {actionResult.verified ? 'valid' : 'invalid'}.
                </div>
              )}
            </div>
          )}
        </article>
      </div>
    </div>
  );
}
