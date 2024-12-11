from fastapi import APIRouter, status, Depends, Request, Response
from fastapi.exceptions import HTTPException
from database import Session,engine
from schemas import SignUpModel,LoginModel
from models import User, TokenLog
from fastapi.exceptions import HTTPException
from werkzeug.security import generate_password_hash , check_password_hash
from fastapi_jwt_auth import AuthJWT
from fastapi.encoders import jsonable_encoder
from middleware.fingerprintHTTP_create import generate_fingerprint
from datetime import datetime
import uuid

auth_router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

session=Session(bind=engine)

@auth_router.get('/')
async def hello(Authorize:AuthJWT=Depends()):

    """
        ## Sample hello world route
    
    """
    try:
        Authorize.jwt_required()

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token, please log in or sign up !"
        )

    return {"message":"Hello World"}

@auth_router.post('/signup',status_code=status.HTTP_201_CREATED)
async def signup(user:SignUpModel):
    """
        ## Create a user
        This requires the following
        ```
                username:int
                email:str
                password:str
                is_staff:bool
                is_active:bool

        ```
    
    """


    db_email=session.query(User).filter(User.email==user.email).first()

    if db_email is not None:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with the email already exists"
        )

    db_username=session.query(User).filter(User.username==user.username).first()

    if db_username is not None:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with the username already exists"
        )

    new_user=User(
        username=user.username,
        email=user.email,
        password=generate_password_hash(user.password),
        is_active=user.is_active,
        is_staff=user.is_staff
    )

    session.add(new_user)

    session.commit()

    return new_user



#login route

@auth_router.post('/login',status_code=200)
async def login(user:LoginModel,request: Request,response: Response, Authorize:AuthJWT=Depends()):
    """     
        ## Login a user
        This requires
            ```
                username:str
                password:str
            ```
        and returns a token pair `access` and `refresh`
    """
    db_user=session.query(User).filter(User.username==user.username).first()

    if db_user and check_password_hash(db_user.password, user.password):
        access_token=Authorize.create_access_token(subject=db_user.username)
        refresh_token=Authorize.create_refresh_token(subject=db_user.username)

        # Create sessionId (sử dụng UUID)
        session_id = str(uuid.uuid4())  
        response.set_cookie(key="sessionId", value=session_id, httponly=True) #store in cookie

        fingerprint = generate_fingerprint(request)

        # Kiểm tra user_id trong bảng token_logs
        existing_tokens = session.query(TokenLog).filter(TokenLog.user_id == db_user.id).all()

        if existing_tokens:
            # exist user in token_logs
            matching_tokens = None
            matching_tokens = [
                token for token in existing_tokens
                if token.fingerprint == fingerprint 
            ]

            if matching_tokens:
                # Trường hợp 1: Cùng fingerprint và sessionId, ghi đè giá trị cột
                for token in matching_tokens:
                    if token.type == "access_token":
                        token.token = access_token
                    elif token.type == "refresh_token":
                        token.token = refresh_token
                    token.created_at = datetime.now()
                    token.session_id = session_id
                    token.root_token=refresh_token
                
                session.commit()
                print(f"Updated tokens for user_id={db_user.id}")
            else:
                # Trường hợp 2: Không trùng fingerprint hoặc sessionId, xử lý như bình thường
                access_log = TokenLog(
                    fingerprint=fingerprint,
                    token=access_token,
                    type="access_token",
                    created_at=datetime.now(),
                    root_token=refresh_token,
                    session_id=session_id,
                    user_id=db_user.id
                )

                refresh_log = TokenLog(
                    fingerprint=fingerprint,
                    token=refresh_token,
                    type="refresh_token",
                    created_at=datetime.now(),
                    root_token=refresh_token,
                    session_id=session_id,
                    user_id=db_user.id
                )

                session.add(access_log)
                session.add(refresh_log)
                session.commit()
                print(f"Added new tokens for user_id={db_user.id}")
        else:
            # Trường hợp không có token của user_id trong bảng, thêm mới
            #first time log in
            access_log = TokenLog(
                fingerprint=fingerprint,
                token=access_token,
                type="access_token",
                created_at=datetime.now(),
                root_token=refresh_token,
                session_id=session_id,
                user_id=db_user.id
            )

            refresh_log = TokenLog(
                fingerprint=fingerprint,
                token=refresh_token,
                type="refresh_token",
                created_at=datetime.now(),
                root_token=refresh_token,
                session_id=session_id,
                user_id=db_user.id
            )

            session.add(access_log)
            session.add(refresh_log)
            session.commit()
            print(f"Added new tokens for user_id={db_user.id}")

        # Trả về token cho người dùng
        response_data = {
            "access": access_token,
            "refresh": refresh_token,
            "sessionId":session_id
        }

        return jsonable_encoder(response_data)


    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid Username Or Password"
    )



#refreshing tokens

@auth_router.get('/refresh1')
async def refresh_token1(Authorize:AuthJWT=Depends()):
    """
    ## Create a fresh token
    This creates a fresh token. It requires an refresh token.
    """


    try:
        Authorize.jwt_refresh_token_required()

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please provide a valid refresh token"
        ) 

    current_user=Authorize.get_jwt_subject()

    
    access_token=Authorize.create_access_token(subject=current_user)

    return jsonable_encoder({"access":access_token})


@auth_router.get('/refresh')
async def refresh_token(request: Request, response: Response, Authorize: AuthJWT = Depends()):
    """
    ## Refresh Access Token
    This endpoint creates a new access token using a valid refresh token.
    """
    try:
        # Kiểm tra refresh token
        Authorize.jwt_refresh_token_required()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please provide a valid refresh token"
        )

    # Lấy refresh token từ header
    authorization_header = request.headers.get("authorization")

    refresh_token = authorization_header.split(" ", 1)[1].strip()

    # Lấy user hiện tại từ token
    current_user = Authorize.get_jwt_subject()
    fingerprint = generate_fingerprint(request)
    session_id = request.cookies.get("sessionId")

    # Kiểm tra trong token_logs
    existing_token = session.query(TokenLog).filter(
        TokenLog.root_token == refresh_token,
        TokenLog.type == "access_token"
    ).first()

    if existing_token:
        # Trường hợp 2: fingerprint và session_id khớp -> ghi đè giá trị access token
        new_access_token = Authorize.create_access_token(subject=current_user)
        existing_token.token = new_access_token
        existing_token.created_at = datetime.now()
        session.commit()
        return jsonable_encoder({"access": new_access_token})

    else:
        # Tạo mới access token và ghi vào bảng token_logs
        new_access_token = Authorize.create_access_token(subject=current_user)
        access_log = TokenLog(
            fingerprint=fingerprint,
            token=new_access_token,
            type="access_token",
            created_at=datetime.now(),
            root_token=refresh_token,
            session_id=session_id,
            user_id=session.query(User).filter(User.username == current_user).first().id
        )
        session.add(access_log)
        session.commit()
        return jsonable_encoder({"access": new_access_token})