from database import engine,Base
from models import User,Order,TokenLog


Base.metadata.create_all(bind=engine)

# File này thường được sử dụng để khởi tạo cơ sở dữ liệu khi bạn thiết lập 
# ứng dụng lần đầu hoặc khi bạn cần tạo lại cấu trúc bảng. 
# Chạy file init_db.py sẽ đảm bảo rằng các bảng trong cơ sở dữ liệu được tạo 
# đúng theo cấu trúc bạn định nghĩa trong các model.