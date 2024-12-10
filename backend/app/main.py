from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from typing import Optional
import jwt
from jose import JWTError
from app.models import User, Base
from app.database import engine, get_db

#initialize FastAPI
app = FastAPI()

#create database tables
Base.metadata.create_all(bind=engine)


#OAuth2 scheme
outh2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(outh2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRECT_KEY, ALGORITHM=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()

SECRECT_KEY = "your_secrect_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password:str) -> bool:
    return pwd_context.verify(plain_password, hash_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwd = jwt.encode(to_encode, SECRECT_KEY, algorithm=ALGORITHM)
    return encoded_jwd


#pydantic model for registration
class RegistrationForm(BaseModel):
    username:str
    email:str
    password:str
    
#pydantic model for login

class LoginForm(BaseModel):
    username:str
    password:str

#Register User
@app.post("/register")
def register_user(registration_form:RegistrationForm, db:Session = Depends(get_db)):
    hashed_password = bcrypt.hash(registration_form.password)
    user = User(username = registration_form.username, email = registration_form.email, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message":"User registered successfully"}


#Login user
@app.post("/login")
def login_user(login_form:LoginForm, db: Session=Depends(get_db)):
    user = db.query(User).filter(User.username == login_form.username).first()
    if not user or not user.verify_password(login_form.password):
        raise HTTPException(status_code=400, detail="Invalid username or password", headers={"WWW-Authenticate":"Bearer"})
    
    token_data = {"sub":user.username}
    access_token = create_access_token(data=token_data)
    return {"access_token": access_token, "token_type":"bearer"}

@app.get("/")
def read_user():
    return {"message":"Amar hello"}



