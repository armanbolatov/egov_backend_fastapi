import os
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import Optional
from fastapi.responses import JSONResponse
import hashlib
import httpx
from sqladmin import Admin, ModelView
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker


Base = declarative_base()
engine = create_engine(
    "sqlite:///database.db",
    connect_args={"check_same_thread": False},
)
Base.metadata.create_all(engine)  # Create tables

class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    iin = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    middle_name = Column(String)
    eng_first_name = Column(String)
    eng_last_name = Column(String)
    date_of_birth = Column(String)
    nationality = Column(String)
    phone_number = Column(String)
    password = Column(String)
    role = Column(Integer)

    def check_password(self, password):
        return self.password == password


app = FastAPI()
admin = Admin(app, engine)


class UserAdmin(ModelView, model=User):
    column_list = [
        User.id,
        User.iin,
        User.first_name,
        User.last_name,
        User.middle_name,
        User.eng_first_name,
        User.eng_last_name,
        User.date_of_birth,
        User.nationality,
        User.phone_number,
        User.password,
        User.role,
    ]


admin.add_view(UserAdmin)
security = HTTPBasic()


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    not_before_policy: Optional[int]  # Make this field optional
    session_state: str
    scope: str


@app.post("/get_token", response_model=TokenResponse)
async def get_token():
    url = "http://hakaton-idp.gov4c.kz/auth/realms/con-web/protocol/openid-connect/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "username": "test-operator",
        "password": "DjrsmA9RMXRl",
        "client_id": "cw-queue-service",
        "grant_type": "password",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, data=data)

    if response.status_code == 200:
        token_data = response.json()
        os.environ["ACCESS_TOKEN"] = token_data["access_token"]
        return token_data
    else:
        raise HTTPException(status_code=response.status_code, detail="Error getting token")


class UserIn(BaseModel):
    iin: str
    password: str


class UserOut(BaseModel):
    first_name: str
    last_name: str
    role: int
    token: str


# Create a scoped session
Session = scoped_session(sessionmaker(bind=engine))

def get_users_from_db():
    session = Session()
    try:
        users = session.query(User).all()
        return users
    finally:
        session.close()


def authenticate(iin: str, password: str):
    users = get_users_from_db()
    user = next((u for u in users if u.iin == iin), None)
    if user is not None and user.check_password(password):
        return user
    return None


@app.post("/login", response_model=UserOut)
def login(credentials: UserIn):
    user = authenticate(credentials.iin, credentials.password)
    if user is not None:
        token = hashlib.md5(f"{user.iin}:{user.password}".encode()).hexdigest()
        return UserOut(
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            token=token,
        )
    else:
        raise HTTPException(status_code=404, detail="User not found")
    

def get_token_from_env():
    token = os.environ.get("ACCESS_TOKEN")
    if token is None:
        raise HTTPException(status_code=401, detail="Token not found")
    return token


@app.get("/persons/{iin}")
async def get_person(iin: str, token: str = Depends(get_token_from_env)):
    url = f"http://hakaton-fl.gov4c.kz/api/persons/{iin}"
    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 200:
        person_data = response.json()
        return person_data
    else:
        raise HTTPException(status_code=response.status_code, detail="Error getting person data")
    

class SmsInput(BaseModel):
    phone: str
    smsText: str


@app.post("/send_sms")
async def send_sms(sms_data: SmsInput, token: str = Depends(get_token_from_env)):
    url = "http://hak-sms123.gov4c.kz/api/smsgateway/send"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    data = {
        "phone": sms_data.phone,
        "smsText": sms_data.smsText,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=data)

    if response.status_code == 200:
        return {"status": "success", "message": "SMS sent successfully"}
    else:
        raise HTTPException(status_code=response.status_code, detail="Error sending SMS")
    

