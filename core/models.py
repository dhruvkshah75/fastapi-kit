from .database import Base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Text
from sqlalchemy.sql.expression import text
from sqlalchemy.sql.sqltypes import TIMESTAMP
from sqlalchemy.orm import relationship


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, nullable=False)
    email = Column(String, nullable=False, unique=True)
    username = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False,
                        server_default=text('now()'))
    

class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, nullable=False)
    key_hash = Column(String, nullable=False, unique=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                      nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'),
                        nullable=False)
    is_active = Column(Boolean, server_default='TRUE', nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=True) 
    # if api key is not used for a long time then the key will be removed
    last_used_at = Column(TIMESTAMP(timezone=True), nullable=True)
    # Nullable means it can last forever
    deactivated_at = Column(TIMESTAMP(timezone=True), nullable=True)

    owner = relationship("User")
