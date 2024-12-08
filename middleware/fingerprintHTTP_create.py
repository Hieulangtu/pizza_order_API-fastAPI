from hashlib import sha256
from fastapi import Request, Depends, HTTPException
from models import TokenLog
from database import Session,engine

session=Session(bind=engine)

def generate_fingerprint(request: Request) -> str:
    """
    Tạo fingerprint từ các thông tin trong header của request.

    Args:
        request (Request): Đối tượng request của FastAPI.

    Returns:
        str: Giá trị hash SHA256 của fingerprint.
    """
    # Lấy thông tin từ headers 
    user_agent = request.headers.get("user-agent", "")
    accept_language = request.headers.get("accept-language", "")
    accept_encoding= request.headers.get("accept-encoding", "")
    sec_ch_ua = request.headers.get("sec-ch-ua", "")
    sec_ch_ua_platform = request.headers.get("sec-ch-ua-platform", "")
    sec_ch_ua_mobile = request.headers.get("sec-ch-ua-mobile", "")
    ip_address = request.client.host


    # Xử lý sec-ch-ua để lấy thông tin trình duyệt chính
    sec_ch_ua_list = [item.strip() for item in sec_ch_ua.split(",")]
    important_sec_ch_ua = sec_ch_ua_list[1] if "Chromium" in sec_ch_ua_list[0] else sec_ch_ua_list[0]

    # Tạo fingerprint string và hash
    fingerprint_string = f"{important_sec_ch_ua}-{user_agent}-{sec_ch_ua_platform}-{accept_language}-{sec_ch_ua_mobile}-{ip_address}-{accept_encoding}"
    fingerprint_hash = sha256(fingerprint_string.encode()).hexdigest()

    with open("fingerprints_log/fingerprintsV3.txt", "a") as log_file:
        log_file.write(f"{fingerprint_hash}   {important_sec_ch_ua}\n\n")

    return fingerprint_hash

async def fingerprint_middleware(request: Request, call_next):
    # Lấy URL từ request
    url_path = request.url.path

    # Trường hợp 1: Nếu URL có đuôi "auth/signup", bỏ qua fingerprint
    if url_path.endswith("auth/signup"):
        return await call_next(request)

    if url_path.endswith("auth/login"):
        return await call_next(request)
    
    if url_path.endswith("openapi.json"):
        return await call_next(request)
    
    if url_path.endswith("8000"):
        return await call_next(request)
    
    
    if url_path.endswith("/docs"):
        return await call_next(request)
    

    

    fingerprint_hash = generate_fingerprint(request)
    #request.state.fingerprint = fingerprint_hash #lưu fingerprint vào request rồi đi tiếp
    token = request.headers.get("authorization").split(" ", 1)[1].strip()

    
    token_entry = session.query(TokenLog).filter(TokenLog.token == token).first()

    # check the existance of fingerprint
    if not token_entry:
        raise HTTPException(status_code=401, detail="Invalid token")

    # checking fingerprint
    if token_entry.fingerprint == fingerprint_hash:
        # Fingerprint khớp, cho phép đi tiếp
        return await call_next(request)
    else:
        # Fingerprint không khớp, yêu cầu đăng nhập lại và xóa token khỏi cơ sở dữ liệu
        session.delete(token_entry)
        session.commit()
        raise HTTPException(status_code=401, detail="Log in again, please")

    response = await call_next(request)
    return response