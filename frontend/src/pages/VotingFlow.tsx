import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { getElection, submitBallot, issueCredential } from '../api';

type Step = 'CREDENTIAL' | 'BALLOT' | 'REVIEW' | 'SUBMITTING' | 'SUCCESS';

export default function VotingFlow() {
  const { id } = useParams();
  const navigate = useNavigate();
  const electionId = Number(id);
  
  const [step, setStep] = useState<Step>('CREDENTIAL');
  const [credentialData, setCredentialData] = useState<any>(null);
  const [selectedOption, setSelectedOption] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  
  const { data: election, isLoading } = useQuery({
    queryKey: ['election', electionId],
    queryFn: () => getElection(electionId),
  });
  
  const issueMutation = useMutation({
    mutationFn: async () => issueCredential(),
    onSuccess: (data) => {
      setCredentialData(data);
      setErrorMsg('');
    },
    onError: (err: any) => {
      setErrorMsg(err.message || 'Failed to issue demo credential');
    }
  });

  const submitMutation = useMutation({
    mutationFn: async () => {
      if (!credentialData) throw new Error("No credential available");
      
      const payload = {
        election_id: electionId,
        credential: credentialData.credential,
        credential_signature_b64: credentialData.credential_signature_b64,
        ballot_plaintext: { selected_option: selectedOption }
      };
      
      const idempotencyKey = `idemp-${Date.now()}`;
      return submitBallot(payload, idempotencyKey);
    },
    onSuccess: () => {
      setStep('SUCCESS');
    },
    onError: (err: any) => {
      setStep('REVIEW');
      setErrorMsg(err.message || 'Submission failed');
    }
  });

  if (isLoading) return <div className="card">Loading election data...</div>;
  if (!election) return <div className="card">Election not found</div>;

  return (
    <div className="card" style={{ maxWidth: '600px', margin: '0 auto' }}>
      <h2 className="card-title">Voting: {election.name || election.params?.name}</h2>
      
      {/* Progress Indicator */}
      <div className="flex gap-2 mb-4">
        {['CREDENTIAL', 'BALLOT', 'REVIEW', 'SUCCESS'].map(s => (
          <div key={s} style={{
            flex: 1, height: '4px', borderRadius: '2px',
            backgroundColor: step === s || (s === 'SUCCESS' && step === 'SUCCESS') ? 'var(--primary)' : 'var(--border-color)'
          }} />
        ))}
      </div>

      {errorMsg && (
        <div className="alert alert-danger" data-testid="error-alert">
          <strong>Error:</strong> {errorMsg}
        </div>
      )}

      {step === 'CREDENTIAL' && (
        <div>
          <p className="mb-4 text-muted">Please obtain your authorized demo voting credential to continue.</p>
          {!credentialData ? (
            <div>
              <button 
                className="btn btn-primary mb-4" 
                onClick={() => issueMutation.mutate()}
                disabled={issueMutation.isPending}
              >
                {issueMutation.isPending ? 'Issuing...' : 'Get Demo Credential'}
              </button>
            </div>
          ) : (
            <div className="mb-4">
              <div className="alert alert-info mb-4" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', color: 'var(--success)' }}>
                <strong>Credential Issued Successfully</strong>
              </div>
              <p><strong>Credential ID:</strong> {credentialData.credential.credential_id}</p>
              <button 
                className="btn btn-primary mt-4" 
                onClick={() => setStep('BALLOT')}
              >
                Continue to Ballot
              </button>
            </div>
          )}
        </div>
      )}

      {step === 'BALLOT' && (
        <div>
          <p className="mb-4 text-muted">Select your candidate for this election.</p>
          <div className="flex flex-col gap-2 mb-4">
            {(election.options || election.params?.options || []).map((opt: string) => (
              <label key={opt} className="flex items-center gap-2" style={{ padding: '0.75rem', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)', cursor: 'pointer' }}>
                <input 
                  type="radio" 
                  name="candidate" 
                  value={opt} 
                  checked={selectedOption === opt}
                  onChange={() => setSelectedOption(opt)}
                />
                {opt}
              </label>
            ))}
          </div>
          <div className="flex justify-between">
            <button className="btn btn-secondary" onClick={() => setStep('CREDENTIAL')}>Back</button>
            <button className="btn btn-primary" disabled={!selectedOption} onClick={() => setStep('REVIEW')}>Review Ballot</button>
          </div>
        </div>
      )}

      {step === 'REVIEW' && (
        <div>
          <div className="alert alert-info mb-4">
            <strong>Review your selection</strong>
            <p>Once submitted, this cannot be undone.</p>
          </div>
          <div className="mb-4 p-4" style={{ backgroundColor: 'var(--bg-main)', borderRadius: 'var(--radius)' }}>
            <p><strong>Candidate:</strong> {selectedOption}</p>
            <p><strong>Credential ID:</strong> {credentialData?.credential?.credential_id}</p>
          </div>
          <div className="flex justify-between">
            <button className="btn btn-secondary" onClick={() => setStep('BALLOT')}>Edit</button>
            <button 
              className="btn btn-primary" 
              onClick={() => {
                setStep('SUBMITTING');
                submitMutation.mutate();
              }}
              disabled={submitMutation.isPending}
            >
              {submitMutation.isPending ? 'Submitting...' : 'Submit Ballot'}
            </button>
          </div>
        </div>
      )}

      {step === 'SUBMITTING' && (
        <div className="text-center py-4">
          <p>Encrypting & submitting ballot to blockchain...</p>
        </div>
      )}

      {step === 'SUCCESS' && (
        <div className="text-center py-4">
          <div className="alert alert-info mb-4" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', color: 'var(--success)' }}>
            <strong>Ballot Successfully Submitted!</strong>
          </div>
          <p className="mb-4">Your ballot has been accepted and committed.</p>
          <button className="btn btn-secondary" onClick={() => navigate('/elections')}>Return to Home</button>
        </div>
      )}
    </div>
  );
}
