from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from passlib.hash import bcrypt

Base = declarative_base()

# User Model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)

    messages_sent = relationship("Message", foreign_keys='Message.sender_id', back_populates="sender")
    messages_received = relationship("Message", foreign_keys='Message.receiver_id', back_populates="receiver")
    contacts = relationship("Contact", back_populates="user")

    def verify_password(self, password: str) -> bool:
        return bcrypt.verify(password, self.hashed_password)

# Message Model
class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="messages_sent")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="messages_received")

# Chat Model
class Chat(Base):
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True, index=True)
    is_group_chat = Column(Boolean, default=False, nullable=False)
    name = Column(String, nullable=True)  # Optional for group chats
    members = relationship("Contact", back_populates="chat")

# Contact Model
class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)

    user = relationship("User", back_populates="contacts")
    chat = relationship("Chat", back_populates="members")
