from hashlib import sha256
from fastapi import Request, Depends, HTTPException
from models import TokenLog
from database import SessionLocal

#session=Session(bind=engine)

def generate_fingerprint(request: Request) -> str:
    """
    Create fingerprint from header in request.

    Args:
        request (Request): object request handled by FastAPI.

    Returns:
        str: value hash SHA256 of fingerprint.
    """
    # Parameters from request's header 
    user_agent = request.headers.get("user-agent", "")
    accept_language = request.headers.get("accept-language", "")
    accept_encoding= request.headers.get("accept-encoding", "")
    sec_ch_ua = request.headers.get("sec-ch-ua", "")
    sec_ch_ua_platform = request.headers.get("sec-ch-ua-platform", "")
    sec_ch_ua_mobile = request.headers.get("sec-ch-ua-mobile", "")
    ip_address = request.client.host


    # Take information about browser
    sec_ch_ua_list = [item.strip() for item in sec_ch_ua.split(",")]
    important_sec_ch_ua = sec_ch_ua_list[1] if "Chromium" in sec_ch_ua_list[0] else sec_ch_ua_list[0]

    # Create request_fingerprint 
    fingerprint_string = f"{important_sec_ch_ua}-{user_agent}-{sec_ch_ua_platform}-{accept_language}-{sec_ch_ua_mobile}-{ip_address}-{accept_encoding}"
    fingerprint_hash = sha256(fingerprint_string.encode()).hexdigest()

    #write to file
    with open("fingerprints_log/fingerprintsV3.txt", "a") as log_file:
        log_file.write(f"{fingerprint_hash}   {important_sec_ch_ua}\n\n")

    return fingerprint_hash

async def fingerprint_middleware(request: Request, call_next):
    # URL from request
    url_path = request.url.path

    # Cases that don't need request_fingerprint (not yet)
    exclude_paths = ["auth/signup", "auth/login", "openapi.json", "8000", "/docs"]
    if any(url_path.endswith(path) for path in exclude_paths):
        return await call_next(request)
    
    #other cases (need request_fingerprint)
    fingerprint_hash = generate_fingerprint(request)
    session_id = request.cookies.get("sessionId")

    

    # checking if header has Authorization 
    authorization_header = request.headers.get("authorization")
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")
    
    #take the token
    token = request.headers.get("authorization").split(" ", 1)[1].strip()

    # create new session for each request middleware
    with SessionLocal() as db:
        token_entry = db.query(TokenLog).filter(TokenLog.token == token).first()
        if not token_entry:
            raise HTTPException(status_code=401, detail="Invalid token-can't be found")

        if token_entry.fingerprint == fingerprint_hash and token_entry.session_id == session_id:
            #check if request has sessionID in cookie (in case two devices have the same request_fingerprint in Local network)
            # OK
            response = await call_next(request)
            return response
        else:
            # fingerprint / sessionId doesn't match=> xoá token
            db.delete(token_entry)
            db.commit()
            raise HTTPException(status_code=401, detail="Log in please")

    # #check if the token has already exist in Table token_logs
    # token_entry = session.query(TokenLog).filter(TokenLog.token == token).first()

    # # check the existance of fingerprint
    # if not token_entry:
    #     raise HTTPException(status_code=401, detail="Invalid token-can't be found")

    # # checking if the token has the same fingerprint and sessionId
    # if token_entry.fingerprint == fingerprint_hash and token_entry.session_id == session_id:
    #     #check if request has sessionID in cookie (in case two devices have the same request_fingerprint in Local network)
    #     # if not session_id:
    #     #   session.delete(token_entry)
    #     #   session.commit()
    #     #   raise HTTPException(
    #     #     status_code=401,
    #     #     detail="Session ID is missing, please log in again"
    #     #   )
    #     # Fingerprint matching
    #     return await call_next(request)
    # else:
    #     # Fingerprint doesm't match, response "log in please" and delete token in token_logs table to protect the user
    #     session.delete(token_entry)
    #     session.commit()
    #     raise HTTPException(status_code=401, detail="Log in , please")

    # response = await call_next(request)
    # return response