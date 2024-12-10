from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from fastapi.security import OAuth2PasswordBearer
import jwt
from app.models import User, Base
from app.database import engine, get_db

#initialize FastAPI
app = FastAPI()

#create database tables
Base.metadata.create_all(bind=engine)


#OAuth2 scheme
outh2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRECT_KEY = "your_secrect_key"

#Register User
@app.post("/register")
def register_user(username: str, email:str, password:str, db:Session = Depends(get_db)):
    hashed_password = bcrypt.hash(password)
    user = User(username = username, email = email, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message":"User registered successfully"}


#Login user
@app.post("/login")
def login_user(username: str, password: str, db: Session=Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.verify_password(password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    token = jwt.encode({"username":user.username}, SECRECT_KEY)
    return {"access_token": token, "token_type":"bearer"}



