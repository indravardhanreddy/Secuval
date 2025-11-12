import ctypes
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import json

# Load the secureapis DLL
secureapis = ctypes.CDLL(r"c:\projects\secureapis\target\release\secureapis.dll")

# Define the SecurityCheckResult struct
class SecurityCheckResult(ctypes.Structure):
    _fields_ = [
        ("allowed", ctypes.c_int32),
        ("status_code", ctypes.c_int32),
        ("error_message", ctypes.POINTER(ctypes.c_char)),
        ("headers_json", ctypes.POINTER(ctypes.c_char)),
    ]

# Define function signatures
secureapis.secureapis_create_config.argtypes = [ctypes.c_char_p]
secureapis.secureapis_create_config.restype = ctypes.c_void_p

secureapis.secureapis_free_security_layer.argtypes = [ctypes.c_void_p]
secureapis.secureapis_free_security_layer.restype = None

secureapis.secureapis_check_request.argtypes = [
    ctypes.c_void_p,  # security_layer
    ctypes.c_char_p,  # method
    ctypes.c_char_p,  # url
    ctypes.c_char_p,  # headers_json
    ctypes.c_char_p,  # body
    ctypes.c_char_p,  # ip
]
secureapis.secureapis_check_request.restype = ctypes.POINTER(SecurityCheckResult)

secureapis.secureapis_free_result.argtypes = [ctypes.POINTER(SecurityCheckResult)]
secureapis.secureapis_free_result.restype = None

secureapis.secureapis_free_string.argtypes = [ctypes.c_void_p]
secureapis.secureapis_free_string.restype = None

# Create security layer with default config
config_json = json.dumps({
    "rate_limit": {"requests_per_minute": 60},
    "validation": {"max_body_size": 1048576},
    "auth": {"enabled": False},
    "cors": {"enabled": True, "allowed_origins": ["*"]},
    "csrf": {"enabled": False},
    "https": {"enforce": False},
    "headers": {"security_headers": True},
    "threat_detection": {"enabled": True},
    "ip_reputation": {"enabled": False},
    "content_type": {"strict": False},
    "request_constraints": {"max_url_length": 2048},
    "method_validation": {"allowed_methods": ["GET", "POST", "PUT", "DELETE"]},
    "cookie_security": {"secure": True},
    "replay_protection": {"enabled": False},
    "monitoring": {"enabled": True},
    "ui": {"enabled": False}
}).encode('utf-8')

security_layer = secureapis.secureapis_create_config(config_json)

class SecureAPIsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Extract request data
        method = request.method.encode('utf-8')
        url = str(request.url).encode('utf-8')
        headers = {k: v for k, v in request.headers.items()}
        headers_json = json.dumps(headers).encode('utf-8')
        body = await request.body()
        ip = request.client.host if request.client else "127.0.0.1"
        ip = ip.encode('utf-8')

        # Call the DLL to check the request
        result_ptr = secureapis.secureapis_check_request(
            security_layer, method, url, headers_json, body, ip
        )

        if result_ptr:
            result = result_ptr.contents
            if result.allowed == 0:
                # Request blocked
                error_msg = ""
                if result.error_message:
                    error_msg = ctypes.c_char_p(result.error_message).value.decode('utf-8')
                secureapis.secureapis_free_result(result_ptr)
                return Response(content=error_msg, status_code=result.status_code)
            else:
                # Request allowed, proceed
                secureapis.secureapis_free_result(result_ptr)
                response = await call_next(request)
                return response
        else:
            # Error in DLL call, allow request
            response = await call_next(request)
            return response

app = FastAPI()
app.add_middleware(SecureAPIsMiddleware)

@app.get("/test")
def test_endpoint():
    return {"message": "SecureAPIs integration test successful."}

@app.on_event("shutdown")
def cleanup():
    if security_layer:
        secureapis.secureapis_free_security_layer(security_layer)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
