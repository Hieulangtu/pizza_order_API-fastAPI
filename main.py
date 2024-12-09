from fastapi import FastAPI, Request
from auth_routes import auth_router
from order_routes import order_router
from fastapi_jwt_auth import AuthJWT
from schemas import Settings
import inspect, re
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.openapi.utils import get_openapi
import json
import time
from middleware_request import LogRequestMiddleware
from hashlib import sha256
from middleware.fingerprintHTTP_create import fingerprint_middleware
from apscheduler.schedulers.background import BackgroundScheduler
from models import delete_expired_tokens
from contextlib import asynccontextmanager


scheduler = BackgroundScheduler()
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Xử lý sự kiện khởi động và tắt ứng dụng bằng Lifespan Event"""
    # Bắt đầu scheduler
    scheduler.add_job(delete_expired_tokens, 'interval', minutes=1)  # Chạy mỗi 1 phút
    scheduler.start()
    print("Scheduler started!")

    # Đoạn code này chạy khi ứng dụng bắt đầu
    yield

    # Đoạn code này chạy khi ứng dụng tắt
    scheduler.shutdown()
    print("Scheduler shut down!")

app=FastAPI(lifespan=lifespan)

#writes requests to requests.txt
app.add_middleware(LogRequestMiddleware)

# @app.middleware("http")
# async def log_full_request(request: Request, call_next):
#     # Log method và URL
#     print(f"Request Method: {request.method}")
#     print(f"Request URL: {request.url}")

#     # Log headers
#     print("Headers:")
#     for key, value in request.headers.items():
#         print(f"    {key}: {value}")

#     # Log query parameters
#     print("Query Parameters:")
#     for key, value in request.query_params.items():
#         print(f"    {key}: {value}")

#     # Log body (nếu có)
#     if request.method in ("POST", "PUT", "PATCH"):
#         body = await request.body()
#         try:
#             # Nếu body là JSON, chuyển đổi và in đẹp hơn
#             print("Body:", json.dumps(json.loads(body), indent=4))
#         except json.JSONDecodeError:
#             print("Body:", body)

#     # Log metadata (nếu có)
#     print("Metadata:")
#     for key, value in request.scope.items():
#         print(f"    {key}: {value}")

#     # Đo thời gian xử lý
#     start_time = time.time()
#     response = await call_next(request)
#     duration = time.time() - start_time
#     print(f"Completed in {duration:.2f} sec\n{'-'*50}")
#     return response

# @app.middleware("http")
# async def fingerprint_middleware(request: Request, call_next):
#     # some signature atttributes from request
#     user_agent = request.headers.get("user-agent", "")
#     accept_language = request.headers.get("accept-language", "")
#     sec_ch_ua = request.headers.get("sec-ch-ua", "")
#     sec_ch_ua_platform = request.headers.get("sec-ch-ua-platform", "")
#     sec_ch_ua_mobile = request.headers.get("sec-ch-ua-mobile", "")

#     #sec-ch-ua handle
#      # Extract only the first meaningful browser info from sec-ch-ua
#     sec_ch_ua_list = [item.strip() for item in sec_ch_ua.split(",")]

#     if "Chromium" in sec_ch_ua_list[0]:
#       important_sec_ch_ua = sec_ch_ua_list[1]  # Nếu phần tử đầu tiên chứa "Chromium", lấy phần tử thứ hai
#     else:
#       important_sec_ch_ua = sec_ch_ua_list[0]  # Nếu không, lấy phần tử đầu tiên

    
#     # hash fingerprint
#     fingerprint_string = f"{important_sec_ch_ua}-{user_agent}-{sec_ch_ua_platform}-{accept_language}-{sec_ch_ua_mobile}"
#     fingerprint_hash = sha256(fingerprint_string.encode()).hexdigest()

#     # print fingerprint 
#     print(f"Fingerprint: {fingerprint_hash}")

#     with open("fingerprintsV2.txt", "a") as log_file:
#         log_file.write(f"{fingerprint_hash}   {important_sec_ch_ua}\n\n")
    
#     response = await call_next(request)
#     return response

app.middleware("http")(fingerprint_middleware)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title = "Pizza Delivery API",
        version = "1.0",
        description = "An API for a Pizza Delivery Service",
        routes = app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "Bearer Auth": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Enter: **'Bearer &lt;JWT&gt;'**, where JWT is the access token"
        }
    }

    # Get all routes where jwt_optional() or jwt_required
    api_router = [route for route in app.routes if isinstance(route, APIRoute)]

    for route in api_router:
        path = getattr(route, "path")
        endpoint = getattr(route,"endpoint")
        methods = [method.lower() for method in getattr(route, "methods")]

        for method in methods:
            # access_token
            if (
                re.search("jwt_required", inspect.getsource(endpoint)) or
                re.search("fresh_jwt_required", inspect.getsource(endpoint)) or
                re.search("jwt_optional", inspect.getsource(endpoint))
            ):
                openapi_schema["paths"][path][method]["security"] = [
                    {
                        "Bearer Auth": []
                    }
                ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@AuthJWT.load_config
def get_config():
    return Settings()

app.include_router(auth_router)
app.include_router(order_router)


