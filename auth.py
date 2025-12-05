from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

fake_user_db = {
    "alice" : {"username" : "alice", "password" : "secret12"}
}

# JWT config
SECRET_KEY = "super-secret-key" #可以隨便寫，但寫完不能隨便改
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIER_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

oauth2_schema = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp" : expire})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encode_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = ALGORITHM)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

def create_refresh_token(data: dict):
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_user_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    access_token = create_access_token({"sub" : user["username"]})
    refresh_token = create_refresh_token({"sub": user["username"]})
    
    response.set_cookie(
        key = "jwt",
        value = access_token,
        httponly = True,
        samesite = "lax"
    )

    response.set_cookie(
        key="refresh",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60 # 7 days
    )

    return {"access_token" : access_token, "token_type" : "bearer"}

@app.get("/user/me")
def me(token: Optional[str] = Depends(oauth2_schema), jwt_cookie: Optional[str] = Cookie(None)):
    if token:
        username = verify_token(token)
    elif jwt_cookie:
        username = verify_token(jwt_cookie)
    else:
        raise HTTPException(status_code=401, detail="Missing token or Cookie")
    
    return {"message" : "Hello, {username}! You are authenticated"}

@app.post("/refresh")
def refresh_token(refresh: Optional[str] = Cookie(None)):
    if refresh is None:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    try:
        payload = jwt.decode(refresh, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # 產生新的 access token
    new_access_token = create_access_token({"sub": username})

    # 產生新的 refresh token（安全性更高）
    new_refresh_token = create_refresh_token({"sub": username})

    # 建立 Response 並寫入 cookies
    response = Response()
    response.set_cookie(
        key="jwt",
        value=new_access_token,
        httponly=True,
        samesite="lax"
    )
    response.set_cookie(
        key="refresh",
        value=new_refresh_token,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60   # 7 天
    )

    return response