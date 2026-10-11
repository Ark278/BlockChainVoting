import asyncio
import base64
from dotenv import load_dotenv
load_dotenv('.env.e2e')
from app.db import get_session_factory
from app.services.blockchain import BlockchainClient
from app.tally.backup_storage import LocalBackupStorage
from app.tally.key_vault import MockElectionKeyVault
from app.tally.audit_log import TallyAuditLog
from app.tally.engine import TallyEngine

async def main():
    sf = get_session_factory()
    async with sf() as session:
        bc = BlockchainClient()
        backup = LocalBackupStorage('/tmp/backups')
        vault = MockElectionKeyVault({5: bytes.fromhex(open('election_sk.hex', 'r').read())})
        audit = TallyAuditLog(session)
        engine = TallyEngine(session, bc, backup, vault, audit, frozenset(['A', 'B', 'C']))
        try:
            res = await engine.run(5)
            print("RESULT:", res)
        except Exception as e:
            print("ERROR:", e)

if __name__ == "__main__":
    asyncio.run(main())
