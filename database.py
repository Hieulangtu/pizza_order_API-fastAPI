from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base,sessionmaker



# Tạo một engine - một đối tượng quản lý kết nối với cơ sở dữ liệu.
engine=create_engine('postgresql://postgres:1905@localhost/pizza_delivery',
    echo=True
)


try:
    # Thử kết nối
    with engine.connect() as connection:
        print("connect successfully to database !")
except Exception as e:
    print("can not connect to database")
    print(e)

Base=declarative_base()

Session=sessionmaker()


# hàm create_engine từ SQLAlchemy, cho phép bạn tạo kết nối tới cơ sở dữ liệu
# declarative_base là một lớp cơ sở (base class) dùng để định nghĩa các mô hình (models) dưới dạng các lớp Python
# sessionmaker là một hàm giúp tạo session để thực hiện các thao tác với cơ sở dữ liệu.