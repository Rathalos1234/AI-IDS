import os, time
from typing import Optional
from passlib.context import CryptContext
import jwt

#we change this later when we do CICD so there are actual tokens also MAKE SURE THEY EXPIRE USE iat from issue_token
JWT_SECRET = os.getenv("JWT_SECRET", "change-me") 
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, hp: str) -> bool:
    return pwd_context.verify(p, hp)

#sighned cookie payload (subject + issue at)
def issue_token(sub: str) -> str:
    payload = {"sub": sub, "iat": int(time.time())}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

#validates the jwt
def decode_token(t: str) -> Optional[dict]:
    try:
        return jwt.decode(t, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None
