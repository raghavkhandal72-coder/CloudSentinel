import uuid
from datetime import datetime

from database import Base
from sqlalchemy import Column, DateTime, String, Text


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    cloud_provider = Column(String, index=True) # AWS or Azure
    resource_id = Column(String)
    finding_title = Column(String)
    why_it_matters = Column(Text)
    evidence = Column(Text)
    cis_benchmark = Column(String)
    risk_level = Column(String) # CRITICAL, HIGH, MEDIUM, LOW, PASSED
    remediation = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
