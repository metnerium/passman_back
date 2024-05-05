import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

# Создание SQLite3 базы данных
engine = create_engine('sqlite:///passwords.db', connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Модель для таблицы пользователей
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)

# Модель для таблицы паролей
class Password(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    website = Column(String)
    login = Column(String)
    password_hash = Column(String)

# Создание таблиц в базе данных
Base.metadata.create_all(bind=engine)

# Контекст для хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Получение сессии для работы с базой данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# FastAPI приложение
app = FastAPI()

# Функция для получения пользователя по имени
def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()

# Функция для хэширования пароля
def hash_password(password: str):
    return pwd_context.hash(password)

# Функция для проверки пароля
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Регистрация нового пользователя
@app.post('/register', status_code=status.HTTP_201_CREATED)
def register(username: str, password: str, db=Depends(get_db)):
    user = get_user(db, username)
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = hash_password(password)
    new_user = User(username=username, password_hash=hashed_password)
    db.add(new_user)
    db.commit()
    return {"message": "User created successfully"}

# Авторизация пользователя
@app.post('/login')
def login(username: str, password: str, db=Depends(get_db)):
    user = get_user(db, username)
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"message": "Login successful"}

# Создание нового пароля
@app.post('/passwords', status_code=status.HTTP_201_CREATED)
def create_password(website: str, login: str, password: str, db=Depends(get_db), user=Depends(get_user)):
    if not user:
        raise HTTPException(status_code=401, detail="User not authenticated")
    hashed_password = hash_password(password)
    new_password = Password(user_id=user.id, website=website, login=login, password_hash=hashed_password)
    db.add(new_password)
    db.commit()
    return {"message": "Password created successfully"}

# Получение всех паролей пользователя
@app.get('/passwords')
def get_passwords(db=Depends(get_db), user=Depends(get_user)):
    if not user:
        raise HTTPException(status_code=401, detail="User not authenticated")
    passwords = db.query(Password).filter(Password.user_id == user.id).all()
    return [{"id": password.id, "website": password.website, "login": password.login} for password in passwords]

# Обновление пароля
@app.put('/passwords/{password_id}')
def update_password(password_id: int, website: str, login: str, password: str, db=Depends(get_db), user=Depends(get_user)):
    if not user:
        raise HTTPException(status_code=401, detail="User not authenticated")
    password_entry = db.query(Password).filter(Password.id == password_id, Password.user_id == user.id).first()
    if not password_entry:
        raise HTTPException(status_code=404, detail="Password not found")
    hashed_password = hash_password(password)
    password_entry.website = website
    password_entry.login = login
    password_entry.password_hash = hashed_password
    db.commit()
    return {"message": "Password updated successfully"}

# Удаление пароля
@app.delete('/passwords/{password_id}')
def delete_password(password_id: int, db=Depends(get_db), user=Depends(get_user)):
    if not user:
        raise HTTPException(status_code=401, detail="User not authenticated")
    password_entry = db.query(Password).filter(Password.id == password_id, Password.user_id == user.id).first()
    if not password_entry:
        raise HTTPException(status_code=404, detail="Password not found")
    db.delete(password_entry)
    db.commit()
    return {"message": "Password deleted successfully"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)