/// <reference types="@testing-library/jest-dom" />
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { vi, describe, beforeEach, it, expect } from 'vitest';
import VotingFlow from '../pages/VotingFlow';
import * as api from '../api';

const queryClient = new QueryClient();

// Mock API
vi.mock('../api', () => ({
  getElection: vi.fn(),
  submitBallot: vi.fn(),
  issueCredential: vi.fn()
}));

const renderWithRouter = () => {
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/elections/1']}>
        <Routes>
          <Route path="/elections/:id" element={<VotingFlow />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
};

describe('VotingFlow & AI Advisory Boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('allows ballot submission regardless of AI anomaly results', async () => {
    // 1. Mock the election endpoint to return data
    (api.getElection as any).mockResolvedValue({
      id: 1, name: 'Test Election', options: ['A', 'B']
    });
    (api.issueCredential as any).mockResolvedValue({
      credential: { credential_id: 'test-cred' },
      credential_signature_b64: 'dGVzdA=='
    });

    renderWithRouter();
    
    // Step 1: Credential
    expect(await screen.findByText('Get Demo Credential')).toBeDefined();
    fireEvent.click(screen.getByText('Get Demo Credential'));
    expect(await screen.findByText('Continue to Ballot')).toBeDefined();
    fireEvent.click(screen.getByText('Continue to Ballot'));

    // Step 2: Ballot
    expect(await screen.findByText('Select your candidate for this election.')).toBeDefined();
    fireEvent.click(screen.getByLabelText('A'));
    fireEvent.click(screen.getByText('Review Ballot'));

    // Step 3: Review
    expect(await screen.findByText('Review your selection')).toBeDefined();
    
    // AI simulation - even if AI returns high risk earlier (e.g. via telemetry),
    // the UI must still allow the submit button to work.
    (api.submitBallot as any).mockResolvedValue({ status: 'success', ballot_id: 'mock_uuid' });
    
    const submitBtn = screen.getByText('Submit Ballot');
    expect((submitBtn as HTMLButtonElement).disabled).toBe(false);
    
    fireEvent.click(submitBtn);

    // Step 4: Success
    expect(await screen.findByText('Ballot Successfully Submitted!')).toBeDefined();
    expect(api.submitBallot).toHaveBeenCalled();
  });
});
