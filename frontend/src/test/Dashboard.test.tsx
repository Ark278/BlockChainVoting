/// <reference types="@testing-library/jest-dom" />
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { vi, describe, beforeEach, it, expect } from 'vitest';
import Dashboard from '../pages/Dashboard';
import * as api from '../api';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } }
});

vi.mock('../api', () => ({
  getAnomalies: vi.fn(),
  getResults: vi.fn()
}));

const renderDashboard = () => {
  render(
    <QueryClientProvider client={queryClient}>
      <Dashboard />
    </QueryClientProvider>
  );
};

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders HIGH_RISK anomaly but clearly labels it ADVISORY ONLY', async () => {
    (api.getAnomalies as any).mockResolvedValue({
      anomalies: [
        {
          result_id: 'test-1',
          bucket_start_ts: 100000,
          risk_level: 'HIGH_RISK',
          anomaly_score: -0.5,
          explanation: 'Rapid submission detected',
          model_version: 'v1'
        }
      ],
      total: 1
    });

    (api.getResults as any).mockResolvedValue({
      valid_ballots: 10,
      invalid_ballots: 0,
      candidate_totals: { A: 10 },
      result_commitment: 'hash'
    });

    renderDashboard();

    // Verify ADVISORY label exists
    expect(await screen.findByText('ADVISORY ONLY')).toBeDefined();
    
    // Verify HIGH_RISK is displayed
    expect(await screen.findByText('HIGH_RISK')).toBeDefined();
    
    // Verify disclaimer
    expect(screen.getByText(/The AI subsystem evaluates behavioral telemetry only/)).toBeDefined();
  });
});
