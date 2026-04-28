import React, { useState } from 'react';

const API_BASE = 'http://127.0.0.1:5000/api';
const BIT_OPTIONS = [1024, 1536, 2048, 3072, 4096, 8192];

export default function HybridDemo() {
  const [senderBits, setSenderBits] = useState(2048);
  const [receiverBits, setReceiverBits] = useState(2048);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const runSimulation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError("Please choose a file.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append("payload_file", file);
    formData.append("sender_bits", senderBits.toString());
    formData.append("receiver_bits", receiverBits.toString());

    try {
      const res = await fetch(`${API_BASE}/hybrid-demo`, {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (data.success) {
        setResult(data.data);
      } else {
        setError(data.error);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-2">
      <div className="panel">
        <h2>Secure File Transfer Simulation</h2>
        <p>
          The sender generates a symmetric session key, encrypts the file with AES-256 CTR, 
          and then encrypts the session key with the receiver's RSA public key. 
          The sender's RSA signature is attached to the ciphertext so the receiver can verify it.
        </p>
        
        <form onSubmit={runSimulation}>
          <div className="grid grid-cols-2" style={{ gap: '1rem', marginBottom: '1rem' }}>
            <div className="input-group">
              <label>Sender RSA key</label>
              <select value={senderBits} onChange={e => setSenderBits(Number(e.target.value))}>
                {BIT_OPTIONS.map(b => <option key={b} value={b}>{b} bits</option>)}
              </select>
            </div>
            <div className="input-group">
              <label>Receiver RSA key</label>
              <select value={receiverBits} onChange={e => setReceiverBits(Number(e.target.value))}>
                {BIT_OPTIONS.map(b => <option key={b} value={b}>{b} bits</option>)}
              </select>
            </div>
          </div>
          
          <div className="input-group">
            <label>Choose file</label>
            <input type="file" onChange={e => setFile(e.target.files?.[0] || null)} />
          </div>

          <button className="btn" type="submit" disabled={loading}>
            {loading ? <><span className="loader"></span> Running Simulation...</> : 'Run simulation'}
          </button>
        </form>

        {error && <div className="status error" style={{ marginTop: '1rem' }}>{error}</div>}
      </div>

      {result && !loading && (
        <div className="panel">
          <h2>Simulation Results</h2>
          <div className={`status ${result.verified && result.restored_matches ? 'ok' : 'error'}`}>
            File: {result.filename} | Signature: {result.verified ? 'passed' : 'failed'} | Data: {result.restored_matches ? 'matches' : 'differs'}
          </div>

          <div className="input-group">
            <label>Session key (Base64)</label>
            <pre>{result.session_key_b64}</pre>
          </div>
          <div className="input-group">
            <label>Encrypted session key (Base64)</label>
            <pre>{result.encrypted_session_key_b64}</pre>
          </div>
          <div className="input-group">
            <label>Nonce & Tag</label>
            <pre>Nonce: {result.nonce_b64}{'\n'}Tag: {result.tag_b64}</pre>
          </div>
          <div className="input-group">
            <label>Ciphertext preview (first 96 bytes)</label>
            <pre>{result.ciphertext_preview_b64}</pre>
          </div>
          <div className="input-group">
            <label>Signature Base64</label>
            <pre>{result.signature_b64}</pre>
          </div>
          
          <div className="input-group">
            <label>Performance</label>
            <pre>
              Input size: {result.input_size} bytes{'\n'}
              Sender keygen: {result.timings.sender_keygen.toFixed(3)} s{'\n'}
              Receiver keygen: {result.timings.receiver_keygen.toFixed(3)} s{'\n'}
              AES encrypt + HMAC: {result.timings.hybrid_encrypt.toFixed(4)} s{'\n'}
              RSA wrap session key: {result.timings.rsa_wrap.toFixed(4)} s{'\n'}
              RSA sign ciphertext: {result.timings.sign.toFixed(4)} s{'\n'}
              RSA unwrap session key: {result.timings.rsa_unwrap.toFixed(4)} s{'\n'}
              RSA verify: {result.timings.verify.toFixed(4)} s{'\n'}
              AES decrypt + HMAC: {result.timings.hybrid_decrypt.toFixed(4)} s
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
