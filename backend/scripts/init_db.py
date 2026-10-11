import asyncio
import os
from dotenv import load_dotenv

load_dotenv(".env.e2e")
from sqlalchemy.ext.asyncio import create_async_engine
from app.models.base import Base
import app.models  # load models

async def main():
    engine = create_async_engine(os.environ["DATABASE_URL"])
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("DB initialized!")

if __name__ == "__main__":
    asyncio.run(main())
