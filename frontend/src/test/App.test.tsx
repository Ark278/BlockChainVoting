/// <reference types="@testing-library/jest-dom" />
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { vi, describe, beforeEach, it, expect } from 'vitest';
import App from '../App';
import * as api from '../api';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false }
  }
});

// Mock API
vi.mock('../api', () => ({
  getElections: vi.fn(),
}));

const renderWithProviders = () => {
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/elections']}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>
  );
};

describe('ElectionList in App', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders dynamic elections from API', async () => {
    (api.getElections as any).mockResolvedValue([
      { 
        id: 10, 
        state: 'VotingOpen',
        params: {
          name: 'Blockchain Voting Demo Election'
        }
      }
    ]);

    renderWithProviders();

    // Verify it loads dynamic data
    expect(await screen.findByText('Blockchain Voting Demo Election')).toBeDefined();
    expect(screen.getByText('Status: VotingOpen')).toBeDefined();

    // Verify the Participate link uses the correct ID
    const participateLink = screen.getByRole('link', { name: 'Participate' });
    expect(participateLink.getAttribute('href')).toBe('/elections/10');
  });

  it('renders "No active elections found." when empty', async () => {
    (api.getElections as any).mockResolvedValue([]);
    renderWithProviders();
    expect(await screen.findByText('No active elections found.')).toBeDefined();
  });
});
