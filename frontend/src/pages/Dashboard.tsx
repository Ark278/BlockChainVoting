import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getAnomalies, getResults } from '../api';

export default function Dashboard() {
  const [electionId, setElectionId] = useState(1);

  const { data: anomaliesData, isLoading: isLoadingAnomalies } = useQuery({
    queryKey: ['anomalies', electionId],
    queryFn: () => getAnomalies(electionId),
  });

  const { data: resultsData, isLoading: isLoadingResults } = useQuery({
    queryKey: ['results', electionId],
    queryFn: () => getResults(electionId),
  });

  return (
    <div>
      <h2 className="mb-4 text-2xl font-bold">Administration & AI Dashboard</h2>
      
      <div className="mb-4">
        <label className="form-label">Select Election ID</label>
        <input 
          type="number" 
          className="form-control" 
          style={{ width: '200px' }}
          value={electionId} 
          onChange={e => setElectionId(Number(e.target.value))} 
        />
      </div>

      <div className="flex flex-col gap-4">
        {/* Results Dashboard */}
        <div className="card">
          <h3 className="card-title">Tally & Results</h3>
          {isLoadingResults ? <p>Loading...</p> : resultsData ? (
            <div>
              <div className="flex gap-4 mb-4">
                <div className="p-4" style={{ flex: 1, backgroundColor: 'var(--bg-main)', borderRadius: 'var(--radius)' }}>
                  <p className="text-muted text-sm">Valid Ballots</p>
                  <p className="text-xl font-bold text-success">{resultsData.valid_ballots}</p>
                </div>
                <div className="p-4" style={{ flex: 1, backgroundColor: 'var(--bg-main)', borderRadius: 'var(--radius)' }}>
                  <p className="text-muted text-sm">Invalid Ballots</p>
                  <p className="text-xl font-bold text-danger">{resultsData.invalid_ballots}</p>
                </div>
              </div>
              
              <h4 className="mb-2 font-bold">Candidate Totals</h4>
              {Object.entries(resultsData.candidate_totals).map(([candidate, count]) => (
                <div key={candidate} className="flex justify-between p-2 border-b border-[var(--border-color)]">
                  <span>{candidate}</span>
                  <strong>{String(count)}</strong>
                </div>
              ))}
              
              <div className="mt-4 p-4" style={{ backgroundColor: 'rgba(59, 130, 246, 0.1)', borderRadius: 'var(--radius)' }}>
                <p className="text-sm font-bold text-[#60a5fa]">Result Commitment</p>
                <code className="text-xs break-all text-[#60a5fa]">{resultsData.result_commitment}</code>
              </div>
            </div>
          ) : <p>No results available.</p>}
        </div>

        {/* AI Anomaly Dashboard */}
        <div className="card">
          <h3 className="card-title flex items-center justify-between">
            AI Anomaly Dashboard
            <span className="text-xs px-2 py-1 bg-[var(--bg-interactive)] rounded text-[var(--text-muted)]">
              ADVISORY ONLY
            </span>
          </h3>
          
          <div className="alert alert-warning mb-4">
            <strong>Advisory Notice:</strong> The AI subsystem evaluates behavioral telemetry only. It does not access ballot contents or voter identities. Risk levels do not confirm fraud and cannot invalidate cryptographically verified ballots.
          </div>

          {isLoadingAnomalies ? <p>Loading...</p> : anomaliesData ? (
            <div className="overflow-x-auto">
              <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <th className="p-2">Bucket Time</th>
                    <th className="p-2">Risk Level</th>
                    <th className="p-2">Score</th>
                    <th className="p-2">Explanation</th>
                    <th className="p-2">Model</th>
                  </tr>
                </thead>
                <tbody>
                  {anomaliesData.anomalies.map((a: any) => (
                    <tr key={a.result_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td className="p-2">{new Date(a.bucket_start_ts * 1000).toLocaleString()}</td>
                      <td className="p-2">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          a.risk_level === 'HIGH_RISK' ? 'bg-[rgba(239,68,68,0.2)] text-[var(--danger)]' : 
                          a.risk_level === 'SUSPICIOUS' ? 'bg-[rgba(245,158,11,0.2)] text-[var(--warning)]' : 
                          'bg-[rgba(16,185,129,0.2)] text-[var(--success)]'
                        }`}>
                          {a.risk_level}
                        </span>
                      </td>
                      <td className="p-2">{a.anomaly_score.toFixed(3)}</td>
                      <td className="p-2 text-sm">{a.explanation}</td>
                      <td className="p-2 text-xs text-muted">{a.model_version}</td>
                    </tr>
                  ))}
                  {anomaliesData.anomalies.length === 0 && (
                    <tr>
                      <td colSpan={5} className="p-4 text-center text-muted">No anomalies detected.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          ) : <p>Failed to load AI data.</p>}
        </div>
      </div>
    </div>
  );
}
