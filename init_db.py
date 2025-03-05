from database import engine,Base
from models import User,Order,TokenLog
import asyncio

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)  # run create_all() with async

if __name__ == "__main__":
    asyncio.run(init_db())

#Base.metadata.create_all(bind=engine)



# File này thường được sử dụng để khởi tạo cơ sở dữ liệu khi bạn thiết lập 
# ứng dụng lần đầu hoặc khi bạn cần tạo lại cấu trúc bảng. 
# Chạy file init_db.py sẽ đảm bảo rằng các bảng trong cơ sở dữ liệu được tạo 
# đúng theo cấu trúc bạn định nghĩa trong các model.