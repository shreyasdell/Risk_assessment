from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from app.core.database import Base


class AuditLog(Base):
    """
    Immutable log of all user actions.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    # Who performed the action
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(100), nullable=True)
    user_role = Column(String(50), nullable=True)

    # What happened
    action = Column(String(50), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False, index=True)
    resource_id = Column(Integer, nullable=True)

    # Details
    description = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)

    # Request metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    # When
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    def __repr__(self):
        return (
            f"<AuditLog user={self.username} "
            f"action={self.action} "
            f"resource={self.resource_type}>"
        )
