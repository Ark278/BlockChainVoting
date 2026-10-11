import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getPublicCommitment } from '../api';

export default function Verification() {
  const [electionId, setElectionId] = useState('');
  const [nullifierHash, setNullifierHash] = useState('');
  
  const [queryParams, setQueryParams] = useState<{e: number, n: string} | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ['verification', queryParams],
    queryFn: () => getPublicCommitment(queryParams!.e, queryParams!.n),
    enabled: !!queryParams,
  });

  const handleVerify = (e: any) => {
    e.preventDefault();
    if (electionId && nullifierHash) {
      setQueryParams({ e: Number(electionId), n: nullifierHash });
    }
  };

  return (
    <div className="card" style={{ maxWidth: '800px', margin: '0 auto' }}>
      <h2 className="card-title">Public Verification</h2>
      <p className="text-muted mb-4">
        Verify that your ballot commitment was published to the blockchain.
      </p>

      <form onSubmit={handleVerify} className="mb-6 p-4" style={{ backgroundColor: 'var(--bg-main)', borderRadius: 'var(--radius)' }}>
        <div className="flex gap-4">
          <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
            <label className="form-label">Election ID</label>
            <input 
              type="number" 
              className="form-control" 
              value={electionId} 
              onChange={e => setElectionId(e.target.value)} 
              required
            />
          </div>
          <div className="form-group" style={{ flex: 3, marginBottom: 0 }}>
            <label className="form-label">Nullifier Hash (Base64)</label>
            <input 
              type="text" 
              className="form-control" 
              value={nullifierHash} 
              onChange={e => setNullifierHash(e.target.value)} 
              placeholder="e.g. v3/...=" 
              required
            />
          </div>
        </div>
        <div className="mt-4 text-right">
          <button type="submit" className="btn btn-primary">Verify Commitment</button>
        </div>
      </form>

      {isLoading && <p>Querying blockchain records...</p>}
      
      {isError && (
        <div className="alert alert-danger">
          <strong>Verification Failed:</strong> Commitment not found or network error.
        </div>
      )}

      {data && (
        <div className="alert alert-info">
          <h3 className="font-bold text-lg mb-2 text-[#60a5fa]">Commitment Confirmed ✓</h3>
          <p className="mb-2 text-[#60a5fa]">
            Your ballot commitment exists on the blockchain and was accepted for this election.
          </p>
          <div className="p-3 mt-4" style={{ backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius)' }}>
            <p className="text-sm font-mono break-all text-[#60a5fa]"><strong className="text-white">Transaction Hash:</strong> {data.tx_hash}</p>
          </div>
          
          <div className="mt-4 p-3 border-t border-[rgba(59,130,246,0.2)]">
            <p className="text-xs text-[#60a5fa]">
              <strong>Note:</strong> This proves your encrypted ballot was received and committed. 
              It does <em>not</em> prove tally correctness. Cryptographic proof of the tally requires 
              independent verification using the published Result Commitment.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
