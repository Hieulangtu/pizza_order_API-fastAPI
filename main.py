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
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from models import delete_expired_tokens
from contextlib import asynccontextmanager


#scheduler = BackgroundScheduler()
scheduler = AsyncIOScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle start and end by Lifespan Event"""
    # start scheduler
    scheduler.add_job(delete_expired_tokens, 'interval', minutes=1)  # run every 1 minute
    scheduler.start()
    print("Scheduler started!")

    # when code starts
    yield

    # when ends
    scheduler.shutdown()
    print("Scheduler shut down!")

app=FastAPI(lifespan=lifespan)

# @app.middleware("http")
# async def add_security_headers(request, call_next):
#     response = await call_next(request)
#     response.headers["Accept-CH"] = "Sec-CH-UA-Model, Sec-CH-UA-Platform, Sec-CH-UA-Mobile"
#     return response

#writes requests to requests.txt
app.add_middleware(LogRequestMiddleware)

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


