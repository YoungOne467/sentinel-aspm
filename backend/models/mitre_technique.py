from sqlalchemy import Column, Integer, String, Table, ForeignKey
from sqlalchemy.orm import relationship
from core.database import Base  # assuming a Base declarative base is defined in backend/models/base.py

# Association table for many-to-many relationship between MitreTechnique and ScanResult
mitre_technique_scan_result = Table(
    "mitre_technique_scan_result",
    Base.metadata,
    Column("mitre_technique_id", Integer, ForeignKey("mitre_technique.id"), primary_key=True),
    Column("finding_id", String, ForeignKey("findings.id"), primary_key=True),
)


class MitreTechnique(Base):
    __tablename__ = "mitre_technique"

    id = Column(Integer, primary_key=True, autoincrement=True)
    technique_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    description = Column(String)

    # Define many-to-many relationship with ScanResult if ScanResult model exists
    scan_results = relationship(
        "ScanResult",
        secondary=mitre_technique_scan_result,
        back_populates="mitre_techniques",
    )
