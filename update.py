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

class NewOrder(Base):
    __tablename__ = "new_orders"

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

def copy_orders_to_new_table():
    session = Session()
    try:
        old_orders = session.query(Order).all()
        for old_order in old_orders:
            new_order = NewOrder(
                id=old_order.id,
                # ... (assign all other columns from the old_order to the new_order)
                courier_id=old_order.courier_id,
            )
            session.add(new_order)
        session.commit()
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

copy_orders_to_new_table()

Order.__table__.drop(engine)

NewOrder.__table__.name = "orders"

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


