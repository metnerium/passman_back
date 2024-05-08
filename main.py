from typing import List
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from pydantic import BaseModel
import bcrypt
import jwt

# Swagger imports
from fastapi.openapi.utils import get_openapi

# Создание базы данных SQLite и подключение к ней
engine = create_engine('sqlite:///passwords.db')
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Модель таблицы пользователей
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    passwords = relationship('Password', back_populates='owner')

# Модель таблицы паролей
class Password(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True, index=True)
    site = Column(String, index=True)
    login = Column(String)
    password = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))
    owner = relationship('User', back_populates='passwords')

# Схемы Pydantic для валидации
class UserCreate(BaseModel):
    username: str
    password: str

class PasswordCreate(BaseModel):
    site: str
    login: str
    password: str

class PasswordResponse(BaseModel):
    id: int
    site: str
    login: str
    password: str

class LoginForm(BaseModel):
    username: str
    password: str
class PasswordUpdate(BaseModel):
    site: str = None
    login: str = None
    password: str = None
# Утилита для получения сессии базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Функция для создания JWT токена
def create_access_token(username: str):
    payload = {'username': username}
    access_token_expires = timedelta(hours=1)
    access_token = jwt.encode(
        {'sub': username, 'exp': datetime.utcnow() + access_token_expires},
        'secret_key',
        algorithm='HS256'
    )
    return access_token

# Функция для аутентификации пользователя и получения токена
def authenticate_user(username: str, password: str, db):
    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return False
    token = create_access_token(username)
    return token

# FastAPI приложение
app = FastAPI()

# Swagger config
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Password Manager API",
        version="1.0.0",
        description="API for managing passwords",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Создание таблиц в базе данных
Base.metadata.create_all(bind=engine)

# Регистрация нового пользователя
@app.post('/register', status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: SessionLocal = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail='Username already exists')
    hashed_password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    new_user = User(username=user.username, password_hash=hashed_password.decode())
    db.add(new_user)
    db.commit()
    return {'message': 'User created successfully'}

# Аутентификация пользователя и получение токена
@app.post('/login', response_model=dict)
def login(form_data: LoginForm, db: SessionLocal = Depends(get_db)):
    token = authenticate_user(form_data.username, form_data.password, db)
    if not token:
        raise HTTPException(status_code=401, detail='Invalid username or password')
    return {'access_token': token, 'token_type': 'bearer'}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Добавление нового пароля для авторизованного пользователя
@app.post('/passwords', response_model=PasswordResponse)
def create_password(password: PasswordCreate, db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        username = payload.get('sub')
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail='Invalid token')
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    new_password = Password(site=password.site, login=password.login, password=password.password, owner=user)
    db.add(new_password)
    db.commit()
    db.refresh(new_password)
    return {"id": new_password.id, "site": new_password.site, "login": new_password.login, "password": new_password.password}

# Получение списка паролей авторизованного пользователя
@app.get('/passwords', response_model=List[PasswordResponse])
def get_passwords(db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        username = payload.get('sub')
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail='Invalid token')
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    passwords = user.passwords
    return [PasswordResponse(id=password.id, site=password.site, login=password.login, password=str(password.password)) for password in passwords]

# Удаление пароля авторизованного пользователя
@app.delete('/passwords/{password_id}')
def delete_password(password_id: int, db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        username = payload.get('sub')
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail='Invalid token')
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    password = db.query(Password).filter(Password.id == password_id, Password.owner == user).first()
    if not password:
        raise HTTPException(status_code=404, detail='Password not found')
    db.delete(password)
    db.commit()
    return {'message': 'Password deleted successfully'}

@app.put('/passwords/{password_id}', response_model=PasswordResponse)
def update_password(password_id: int, password_update: PasswordUpdate, db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        username = payload.get('sub')
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail='Invalid token')

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')

    password = db.query(Password).filter(Password.id == password_id, Password.owner == user).first()
    if not password:
        raise HTTPException(status_code=404, detail='Password not found')

    # Обновление полей пароля
    if password_update.site:
        password.site = password_update.site
    if password_update.login:
        password.login = password_update.login
    if password_update.password:
        password.password = password_update.password

    db.commit()
    db.refresh(password)

    return {'message': 'Password updated successfully'}