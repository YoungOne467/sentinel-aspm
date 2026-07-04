import logging
from .database import AsyncSessionLocal
from .models import ThreatIntel
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

async def save_intel(vuln_type: str, status_code: int, original_payload: str, winning_payload: str, ai_analysis: str):
    """
    Saves a successful evasion payload to the Threat Intelligence DB using SQLAlchemy.
    """
    status_str = str(status_code)
    
    async with AsyncSessionLocal() as session:
        # Check if we already have this winning payload for this exact scenario
        stmt = select(ThreatIntel).where(
            ThreatIntel.vuln_type == vuln_type.lower(),
            ThreatIntel.status_code == status_str,
            ThreatIntel.winning_payload == winning_payload
        )
        result = await session.execute(stmt)
        existing = result.scalars().first()
        
        if not existing:
            new_intel = ThreatIntel(
                vuln_type=vuln_type.lower(),
                status_code=status_str,
                original_payload=original_payload,
                winning_payload=winning_payload,
                ai_analysis=ai_analysis
            )
            session.add(new_intel)
            await session.commit()
            logger.info("Saved new evasion intelligence for %s (Status %s)", vuln_type, status_code)

async def query_intel(vuln_type: str, status_code: int) -> list:
    """
    Retrieves a list of known successful evasion payloads for a given vulnerability and error code.
    """
    status_str = str(status_code)
    
    async with AsyncSessionLocal() as session:
        stmt = select(ThreatIntel.winning_payload).where(
            ThreatIntel.vuln_type == vuln_type.lower(),
            ThreatIntel.status_code == status_str
        )
        result = await session.execute(stmt)
        return [row[0] for row in result.all()]
