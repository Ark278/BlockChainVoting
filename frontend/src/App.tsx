import { Routes, Route, Link } from 'react-router-dom';
import VotingFlow from './pages/VotingFlow';
import Dashboard from './pages/Dashboard';
import Verification from './pages/Verification';

const Landing = () => (
  <div className="card">
    <h2 className="card-title">Welcome to the Secure Voting Protocol</h2>
    <p className="text-muted mb-4">A high-assurance, post-quantum resilient voting system demo.</p>
    <Link to="/elections" className="btn btn-primary">View Elections</Link>
  </div>
);

import { useQuery } from '@tanstack/react-query';
import { getElections } from './api';

const ElectionList = () => {
  const { data: elections, isLoading, isError } = useQuery({
    queryKey: ['elections'],
    queryFn: getElections,
  });

  if (isLoading) return <div className="card">Loading active elections...</div>;
  if (isError) return <div className="card">Failed to load elections.</div>;

  return (
    <div className="card">
      <h2 className="card-title">Active Elections</h2>
      <div className="mt-4">
        {elections?.length === 0 && <p className="text-muted">No active elections found.</p>}
        {elections?.map((election: any) => {
          const electionName = election.params?.name || election.name || 'Unnamed Election';
          const electionStatus = election.state || election.status || 'UNKNOWN';
          return (
            <div key={election.id} className="flex justify-between items-center mb-2 p-4" style={{ border: '1px solid var(--border-color)', borderRadius: 'var(--radius)' }}>
              <div>
                <h3>{electionName}</h3>
                <span className="text-muted" style={{ fontSize: '0.875rem' }}>Status: {electionStatus}</span>
              </div>
              <Link to={`/elections/${election.id}`} className="btn btn-secondary">Participate</Link>
            </div>
          );
        })}
      </div>
    </div>
  );
};

function App() {
  return (
    <div className="app-container">
      <header>
        <Link to="/" className="logo">BlockChainVoting UI</Link>
        <nav className="flex gap-4 items-center">
          <Link to="/elections" className="text-muted" style={{ textDecoration: 'none' }}>Elections</Link>
          <Link to="/verify" className="text-muted" style={{ textDecoration: 'none' }}>Public Verification</Link>
          <Link to="/dashboard" className="text-muted" style={{ textDecoration: 'none' }}>Dashboard</Link>
        </nav>
      </header>
      
      <main>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/elections" element={<ElectionList />} />
          <Route path="/elections/:id" element={<VotingFlow />} />
          <Route path="/verify" element={<Verification />} />
          <Route path="/dashboard" element={<Dashboard />} />
        </Routes>
      </main>
      
      <footer>
        <p>This is a research/demo environment. Not certified for government elections.</p>
        <p className="mt-2 text-muted">Architecture v2.6</p>
      </footer>
    </div>
  );
}

export default App;
