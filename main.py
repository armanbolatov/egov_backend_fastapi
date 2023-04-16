import os
import random
from typing import List
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from fastapi.responses import JSONResponse
import hashlib
import httpx
from sqladmin import Admin, ModelView
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker, aliased


Base = declarative_base()
engine = create_engine(
    "sqlite:///database.db",
    connect_args={"check_same_thread": False},
)
security = HTTPBasic()
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
admin = Admin(app, engine)


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
    

class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True)
    name = Column(String)


class CourierCompanies(Base):
    __tablename__ = "courier_companies"

    id = Column(Integer, primary_key=True)
    courier_id = Column(Integer)
    company_id = Column(Integer)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True)
    order_number = Column(String)
    service_name = Column(String)
    department = Column(String)
    recipient_iin = Column(String)
    recipient_first_name = Column(String)
    recipient_last_name = Column(String)
    recipient_phone_number = Column(String)
    delivery_region = Column(String)
    delivery_city = Column(String)
    delivery_street = Column(String)
    delivery_house_number = Column(String)
    delivery_apartment_number = Column(String)
    delivery_entrance_number = Column(String)
    delivery_floor_number = Column(String)
    delivery_building_number = Column(String)
    delivery_residential_complex_name = Column(String)
    delivery_additional_information = Column(String)
    courier_id = Column(Integer, nullable=True)
    otp = Column(String, nullable=True) # One time password
    status = Column(Integer, nullable=True) # 0 - not delivered, 1 - delivered


class OrderData(BaseModel):
    orderNumber: str
    serviceName: str
    department: str
    recipientInfo: dict


Base.metadata.create_all(engine)  # Create tables


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


class OrderAdmin(ModelView, model=Order):
    column_list = [
        Order.id,
        Order.order_number,
        Order.service_name,
        Order.department,
        Order.recipient_iin,
        Order.recipient_first_name,
        Order.recipient_last_name,
        Order.recipient_phone_number,
        Order.delivery_region,
        Order.delivery_city,
        Order.delivery_street,
        Order.delivery_house_number,
        Order.delivery_apartment_number,
        Order.delivery_entrance_number,
        Order.delivery_floor_number,
        Order.delivery_building_number,
        Order.delivery_residential_complex_name,
        Order.delivery_additional_information,
        Order.courier_id,
        Order.otp,
        Order.status,
    ]
admin.add_view(OrderAdmin)


class CompanyAdmin(ModelView, model=Company):
    column_list = [
        Company.id,
        Company.name,
    ]
admin.add_view(CompanyAdmin)


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    not_before_policy: Optional[int]
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


Session = scoped_session(sessionmaker(bind=engine)) # Create a scoped session


class UserIn(BaseModel):
    iin: str
    password: str


class UserOut(BaseModel):
    id: int
    first_name: str
    last_name: str
    role: int
    token: str


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
            id=user.id,
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
    

@app.get("/get_phone_number/{iin}")
async def get_phone_number(iin: str, token: str = Depends(get_token_from_env)):
    url = f"http://hakaton.gov4c.kz/api/bmg/check/{iin}/"
    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 200:
        phone_number = response.json()
        return phone_number
    else:
        raise HTTPException(status_code=response.status_code, detail="Error getting phone number")
    

@app.post("/save_order")
def save_order(order_data: OrderData):
    session = Session()
    try:
        order = Order(
            order_number=order_data.orderNumber,
            service_name=order_data.serviceName,
            department=order_data.department,
            recipient_iin=order_data.recipientInfo["iin"],
            recipient_first_name=order_data.recipientInfo["firstName"],
            recipient_last_name=order_data.recipientInfo["lastName"],
            recipient_phone_number=order_data.recipientInfo["phoneNumber"],
            delivery_region=order_data.recipientInfo["deliveryAddress"]["region"],
            delivery_city=order_data.recipientInfo["deliveryAddress"]["city"],
            delivery_street=order_data.recipientInfo["deliveryAddress"]["street"],
            delivery_house_number=order_data.recipientInfo["deliveryAddress"]["houseNumber"],
            delivery_apartment_number=order_data.recipientInfo["deliveryAddress"]["apartmentNumber"],
            delivery_entrance_number=order_data.recipientInfo["deliveryAddress"]["entranceNumber"],
            delivery_floor_number=order_data.recipientInfo["deliveryAddress"]["floorNumber"],
            delivery_building_number=order_data.recipientInfo["deliveryAddress"]["buildingNumber"],
            delivery_residential_complex_name=order_data.recipientInfo["deliveryAddress"]["residentialComplexName"],
            delivery_additional_information=order_data.recipientInfo["deliveryAddress"]["additionalInformation"],
            courier_id="n/a",
            status=0,
            otp="empty",
        )
        session.add(order)
        session.commit()
        return {"message": "Order saved successfully", "order_id": order.id}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


class AssignCourierInput(BaseModel):
    order_number: str
    courier_id: int


def assign_courier_to_order(order_number: str, courier_id: int):
    session = Session()
    try:
        order = session.query(Order).filter(Order.order_number == order_number).first()
        if order is not None:
            order.courier_id = courier_id
            session.commit()
            return {
                "message": "Courier assigned successfully",
                "order_id": order_number,
                "courier_id": courier_id,
                "otp": order.otp,
            }
        else:
            raise HTTPException(status_code=404, detail="Order not found")
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


def generate_otp(length: int = 6) -> str:
    return "".join(random.choices("0123456789", k=length))


@app.post("/assign_courier")
def assign_courier(assign_courier_data: AssignCourierInput):
    session = Session()
    try:
        order = session.query(Order).filter(Order.order_number == assign_courier_data.order_number).first()
        if order is not None:
            order.otp = generate_otp()
            session.commit()
        else:
            raise HTTPException(status_code=404, detail="Order not found")
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    return assign_courier_to_order(assign_courier_data.order_number, assign_courier_data.courier_id)


class OrderOut(BaseModel):
    id: int
    order_number: str
    service_name: str
    department: str
    recipient_iin: str
    recipient_first_name: str
    recipient_last_name: str
    recipient_phone_number: str
    delivery_region: str
    delivery_city: str
    delivery_street: str
    delivery_house_number: str
    delivery_apartment_number: str
    delivery_entrance_number: str
    delivery_floor_number: str
    delivery_building_number: str
    delivery_residential_complex_name: str
    delivery_additional_information: str
    courier_id: str
    otp: str


def get_orders_for_courier(courier_id: int):
    session = Session()
    try:
        orders = session.query(Order).filter(Order.courier_id == courier_id).filter(Order.status == 0).all()
        return orders
    finally:
        session.close()


@app.get("/courier/{courier_id}/orders", response_model=List[OrderOut])
def get_courier_orders(courier_id: int):
    orders = get_orders_for_courier(courier_id)
    return [OrderOut(**order.__dict__) for order in orders]


def get_unassigned_orders():
    session = Session()
    try:
        orders = session.query(Order).filter(Order.courier_id == None).all()
        return orders
    finally:
        session.close()


@app.get("/unassigned_orders", response_model=List[OrderOut])
def get_available_orders():
    orders = get_unassigned_orders()
    return [OrderOut(**order.__dict__) for order in orders]


@app.get("/orders", response_model=List[OrderOut])
def get_all_orders():
    session = Session()
    try:
        orders = session.query(Order).all()
        return [OrderOut(**order.__dict__) for order in orders]
    finally:
        session.close()


class CompanyName(BaseModel):
    courier_id: int
    company_name: str


def get_company_name_for_courier():
    session = Session()
    try:
        company_alias = aliased(Company)
        result = (
            session.query(CourierCompanies.courier_id, company_alias.name)
            .join(company_alias, CourierCompanies.company_id == company_alias.id)
            .all()
        )
        return result
    finally:
        session.close()


@app.get("/courier_companies", response_model=List[CompanyName])
def get_courier_companies():
    company_names = get_company_name_for_courier()
    return [CompanyName(courier_id=courier_id, company_name=company_name) for courier_id, company_name in company_names]


@app.post("/check_otp")
def check_otp(order_number: str, otp: str):
    session = Session()
    try:
        order = session.query(Order).filter(Order.order_number == order_number).first()
        if order is not None:
            if order.otp == otp:
                order.status = 1
                session.commit()
                return {"message": "OTP is correct"}
            else:
                return {"message": "OTP is incorrect"}
        else:
            raise HTTPException(status_code=404, detail="Order not found")
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()