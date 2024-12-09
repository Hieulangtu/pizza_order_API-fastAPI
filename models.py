from database import Base, Session,engine
from sqlalchemy import Column,Integer,Boolean,Text,String,ForeignKey,DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship,Session
from sqlalchemy_utils.types import ChoiceType
from datetime import datetime, timedelta

session=Session(bind=engine)

class User(Base):
    __tablename__='user'
    id=Column(Integer,primary_key=True)
    username=Column(String(25),unique=True)
    email=Column(String(80),unique=True)
    password=Column(Text,nullable=True)
    is_staff=Column(Boolean,default=False)
    is_active=Column(Boolean,default=False)
    orders=relationship('Order',back_populates='user')
    token_logs=relationship('TokenLog',back_populates='user')


    def __repr__(self):
        return f"<User {self.username}>"


class Order(Base):

    ORDER_STATUSES=(
        ('PENDING','pending'),
        ('IN-TRANSIT','in-transit'),
        ('DELIVERED','delivered')

    )

    PIZZA_SIZES=(
        ('SMALL','small'),
        ('MEDIUM','medium'),
        ('LARGE','large'),
        ('EXTRA-LARGE','extra-large')
    )


    __tablename__='orders'
    id=Column(Integer,primary_key=True)
    quantity=Column(Integer,nullable=False)
    order_status=Column(ChoiceType(choices=ORDER_STATUSES),default="PENDING")
    pizza_size=Column(ChoiceType(choices=PIZZA_SIZES),default="SMALL")
    user_id=Column(Integer,ForeignKey('user.id'))
    user=relationship('User',back_populates='orders')

    def __repr__(self):
        return f"<Order {self.id}>"
    

class TokenLog(Base):
    __tablename__ = 'token_logs'

    id = Column(Integer, primary_key=True)
    fingerprint = Column(String(128), nullable=False)  # SHA256 hash
    token = Column(Text, nullable=False)  # JWT token
    type=Column(Text,nullable=False)
    root_token = Column(Text, nullable=True)
    session_id = Column(String(64), nullable=True) 
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())  # Thời gian tạo

    user=relationship("User",back_populates="token_logs")

    def __repr__(self):
        return f"<TokenLog(id={self.id}, fingerprint={self.fingerprint[:8]}...)>"
    

def delete_expired_tokens():
    """Xóa các token hết hạn dựa trên type và created_at."""
    # Xóa các access token hết hạn (quá 15 phút)
    deleted_access = session.query(TokenLog).filter(
        TokenLog.type == 'access',
        TokenLog.created_at < datetime.now() - timedelta(minutes=15)
    ).delete(synchronize_session=False)


    # Xóa các refresh token hết hạn (quá 7 ngày)
    deleted_refresh = session.query(TokenLog).filter(
        TokenLog.type == 'refresh',
        TokenLog.created_at < datetime.now() - timedelta(days=7)
    ).delete(synchronize_session=False)

    # Lưu thay đổi vào cơ sở dữ liệu
    session.commit()

    print(f"[{datetime.now()}]: delete {deleted_access} access tokens and {deleted_refresh} refresh tokens.")