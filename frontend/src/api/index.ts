import { computeClientBucketToken, getCurrentHourTs } from '../telemetry';

const API_BASE = '/api/v1';

export class ApiError extends Error {
  public status: number;
  public details: any;
  
  constructor(message: string, status: number, details?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

async function fetchWithTelemetry(url: string, options: RequestInit = {}) {

  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');
  // Pass telemetry headers or include them in payloads where required by backend
  // For POST /api/v1/telemetry, it goes in body
  
  const res = await fetch(url, { ...options, headers });
  
  if (!res.ok) {
    let details;
    try {
      details = await res.json();
    } catch {
      // Ignored
    }
    throw new ApiError(`Request failed with status ${res.status}`, res.status, details);
  }
  
  return res.json();
}

// ── Types ───────────────────────────────────────────────────────────────────

export interface TelemetryPayload {
  election_id: number;
  bucket_start_ts: number;
  client_bucket_token_hex: string;
  submission_interval_seconds?: number;
  submission_attempts?: number;
  auth_failure_count?: number;
  encrypted_blob_size_bytes?: number;
  behavioral_signal_hex?: string;
}

export interface Anomaly {
  result_id: string;
  election_id: number;
  telemetry_bucket_id_hex: string;
  bucket_start_ts: number;
  anomaly_score: number;
  risk_level: 'NORMAL' | 'SUSPICIOUS' | 'HIGH_RISK' | 'UNAVAILABLE';
  model_version: string;
  explanation: string;
  created_at: string;
}

// ── API Methods ─────────────────────────────────────────────────────────────

export async function getElections() {
  return fetchWithTelemetry(`${API_BASE}/elections`);
}

export async function getElection(id: number) {
  return fetchWithTelemetry(`${API_BASE}/elections/${id}`);
}

export async function submitBallot(payload: any, idempotencyKey: string) {
  const headers = { 'Idempotency-Key': idempotencyKey, 'Content-Type': 'application/json' };
  const res = await fetch(`${API_BASE}/ballots/submit`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload)
  });
  
  if (!res.ok) {
    const details = await res.json().catch(() => ({}));
    throw new ApiError(`Ballot submission failed`, res.status, details);
  }
  return res.json();
}

export async function postTelemetry(payload: Omit<TelemetryPayload, 'client_bucket_token_hex' | 'bucket_start_ts'>) {
  const bucketStart = getCurrentHourTs();
  const clientBucketTokenHex = computeClientBucketToken(bucketStart);
  
  const fullPayload: TelemetryPayload = {
    ...payload,
    bucket_start_ts: bucketStart,
    client_bucket_token_hex: clientBucketTokenHex
  };
  
  return fetchWithTelemetry(`${API_BASE}/telemetry`, {
    method: 'POST',
    body: JSON.stringify(fullPayload)
  });
}

export async function getAnomalies(electionId?: number): Promise<{ anomalies: Anomaly[], total: number }> {
  const url = new URL(`${window.location.origin}${API_BASE}/anomalies`);
  if (electionId) url.searchParams.append('election_id', electionId.toString());
  
  return fetchWithTelemetry(url.toString());
}

export async function getPublicCommitment(electionId: number, nullifierHashBase64: string) {
  return fetchWithTelemetry(`${API_BASE}/commitments/${electionId}/${encodeURIComponent(nullifierHashBase64)}`);
}

export async function getResults(electionId: number) {
  return fetchWithTelemetry(`${API_BASE}/results/${electionId}`);
}
export async function issueCredential() {
  return fetchWithTelemetry(`${API_BASE}/demo/credentials`, {
    method: 'POST'
  });
}
