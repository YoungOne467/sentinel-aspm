import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update, insert
# from ..models import MitreTechnique  # Adjust import if necessary

async def sync_mitre(async_session: AsyncSession) -> None:
    """Synchronize MITRE ATT&CK techniques.

    Fetches the latest STIX bundle from MITRE, extracts ``attack-pattern`` objects,
    and upserts them into the ``mitre_technique`` table.
    """
    url = "https://cti-taxii.mitre.org/stix/attack/latest/"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=30.0)
        resp.raise_for_status()
        bundle = resp.json()

    objects = bundle.get("objects", [])
    async with async_session.begin():
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            # Extract technique ID from external references
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            if not technique_id:
                continue
            name = obj.get("name")
            description = obj.get("description", "")
            # Try to update existing record
            upd = (
                update(MitreTechnique)
                .where(MitreTechnique.technique_id == technique_id)
                .values(name=name, description=description)
                .execution_options(synchronize_session="fetch")
            )
            result = await async_session.execute(upd)
            if result.rowcount == 0:
                ins = insert(MitreTechnique).values(
                    technique_id=technique_id, name=name, description=description
                )
                await async_session.execute(ins)
