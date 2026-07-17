from fastapi import FastAPI, HTTPException, status, Depends
from sqlalchemy.orm import Session
from database_model import User, UserRole 
import model
from db import get_db
from hash import hash_password

app = FastAPI()


@app.post("/users", response_model=model.UserRead, status_code=status.HTTP_201_CREATED)
def create_user(user_in: model.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email already registered"
        )

    hashed_password = hash_password(user_in.password)

    new_user = User(
        email=user_in.email,
        password_hash=hashed_password,
        role=UserRole.USER
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

