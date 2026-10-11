import asyncio
import logging
logging.basicConfig(level=logging.INFO)

from dotenv import load_dotenv
load_dotenv('.env.e2e')

from app.db.session import _get_session_factory
async_session_maker = _get_session_factory()
from app.services.blockchain import BlockchainClient
from app.tally.backup_storage import LocalFilesystemBackupStorage
from app.tally.audit_log import TallyAuditLog
from app.tally.engine import TallyEngine

class MockElectionKeyVault:
    def __init__(self, keys):
        self.keys = keys
    def get_kem_sk(self, eid):
        return self.keys[eid]

async def main():
    with open("election_sk.hex", "r") as f:
        elec_sk = bytes.fromhex(f.read().strip())
    
    async with async_session_maker() as session:
        bc = BlockchainClient(rest_url="http://127.0.0.1:1317")
        backup = LocalFilesystemBackupStorage("/tmp/backups")
        vault = MockElectionKeyVault({5: elec_sk})
        audit = TallyAuditLog()
        engine = TallyEngine(session, bc, backup, vault, audit, allowed_options=frozenset(["Alice", "Bob"]))
        
        try:
            result = await engine.run(5)
            print(f"    - SUCCESS: Tally Result Counters: {result.counters}")
        except Exception as e:
            print(f"    - Tally Engine Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
