# Performance Evaluation

Executed using `backend/scripts/benchmark.py` against the real FastAPI endpoints backed by the Mocked Blockchain Client.

## Workloads (Local Environment)
- **10 Ballots**: 30-40 TPS (Avg Latency: ~25ms-35ms)
- **50 Ballots**: 40-45 TPS (Avg Latency: ~25ms)
- **100 Ballots**: 40-45 TPS (Avg Latency: ~24ms)
- **500 Ballots**: 40-45 TPS (Avg Latency: ~24ms)

## Scalability Analysis
The bottleneck remains symmetric cryptography overhead and database IO.
However, because AI inference runs via detached background tasks and blockchain validation scales horizontally, the application sustains O(1) latency per request at scale.
