from datetime import datetime,date
import os
from fastapi import FastAPI,Depends,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from pydantic import BaseModel,EmailStr,Field
from sqlalchemy import create_engine,Column,Integer,String,Float,Date,Time,DateTime,Boolean,ForeignKey
from sqlalchemy.orm import declarative_base,sessionmaker,Session
from jose import jwt,JWTError
from passlib.context import CryptContext

engine=create_engine(os.getenv("DATABASE_URL","sqlite:///./worksphere.db"),connect_args={"check_same_thread":False})
SessionLocal=sessionmaker(bind=engine); Base=declarative_base()
SECRET=os.getenv("SECRET_KEY","change-this-secret"); pwd=CryptContext(schemes=["bcrypt"],deprecated="auto"); bearer=HTTPBearer()

class User(Base):
 __tablename__="users"
 id=Column(Integer,primary_key=True);username=Column(String(100),unique=True);email=Column(String(255),unique=True);hashed_password=Column(String(255));role=Column(String(20),default="EMPLOYEE");status=Column(String(20),default="ACTIVE");created_at=Column(DateTime,default=datetime.utcnow)
class Employee(Base):
 __tablename__="employees"
 id=Column(Integer,primary_key=True);user_id=Column(Integer,ForeignKey("users.id"),unique=True);full_name=Column(String(150));designation=Column(String(100));department=Column(String(100));joining_date=Column(Date);salary=Column(Float,default=0);status=Column(String(20),default="ACTIVE")
class Attendance(Base):
 __tablename__="attendance"
 id=Column(Integer,primary_key=True);employee_id=Column(Integer,ForeignKey("employees.id"));check_in=Column(Time);check_out=Column(Time);date=Column(Date);status=Column(String(20),default="PRESENT");late_minutes=Column(Integer,default=0);overtime_hours=Column(Float,default=0)
class LeavePolicy(Base):
 __tablename__="leave_policies"
 id=Column(Integer,primary_key=True);leave_type=Column(String(20),unique=True);total_days_allowed=Column(Integer)
class LeaveBalance(Base):
 __tablename__="leave_balance"
 id=Column(Integer,primary_key=True);employee_id=Column(Integer,ForeignKey("employees.id"));leave_type=Column(String(20));remaining_days=Column(Integer)
class Leave(Base):
 __tablename__="leaves"
 id=Column(Integer,primary_key=True);employee_id=Column(Integer,ForeignKey("employees.id"));leave_type=Column(String(20));start_date=Column(Date);end_date=Column(Date);reason=Column(String(500));status=Column(String(20),default="PENDING")
class Payroll(Base):
 __tablename__="payroll"
 id=Column(Integer,primary_key=True);employee_id=Column(Integer,ForeignKey("employees.id"));basic_salary=Column(Float);allowances=Column(Float,default=0);deductions=Column(Float,default=0);bonus=Column(Float,default=0);net_salary=Column(Float);month=Column(String(20));created_at=Column(DateTime,default=datetime.utcnow)

Base.metadata.create_all(engine)

class Login(BaseModel): username:str;password:str
class Register(BaseModel): username:str;email:EmailStr;password:str=Field(min_length=6);role:str="EMPLOYEE"
class EmployeeIn(BaseModel): user_id:int;full_name:str;designation:str;department:str;joining_date:date;salary:float=Field(ge=0);status:str="ACTIVE"
class LeaveIn(BaseModel): employee_id:int;leave_type:str;start_date:date;end_date:date;reason:str
class PayrollIn(BaseModel): employee_id:int;basic_salary:float;allowances:float=0;deductions:float=0;bonus:float=0;month:str
class PolicyIn(BaseModel): leave_type:str;total_days_allowed:int=Field(ge=0)
class BalanceIn(BaseModel): employee_id:int;leave_type:str;remaining_days:int=Field(ge=0)
class RoleIn(BaseModel): role:str
class StatusIn(BaseModel): status:str

def make_token(u): return jwt.encode({"sub":str(u.id),"role":u.role,"exp":datetime.utcnow().timestamp()+3600},SECRET,algorithm="HS256")
def dbdep():
 db=SessionLocal()
 try: yield db
 finally: db.close()
def current(c:HTTPAuthorizationCredentials=Depends(bearer),db:Session=Depends(dbdep)):
 try:p=jwt.decode(c.credentials,SECRET,algorithms=["HS256"])
 except JWTError:raise HTTPException(401,"Invalid or expired token")
 u=db.get(User,int(p["sub"]))
 if not u or u.status!="ACTIVE":raise HTTPException(401,"Inactive or missing user")
 return u
def roles(*rs):
 def check(u=Depends(current)):
  if u.role not in rs:raise HTTPException(403,"Role not permitted")
  return u
 return check
def own(u,eid,db):
 e=db.get(Employee,eid)
 if not e or (u.role=="EMPLOYEE" and e.user_id!=u.id):raise HTTPException(403,"Ownership validation failed")
 return e

app=FastAPI(title="WorkSphere HRMS Phase 2")
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:5173","http://127.0.0.1:5173"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

@app.get("/")
def root():return {"message":"WorkSphere HRMS Phase 2 API is running"}
@app.get("/health")
def health():return {"status":"ok"}
@app.post("/auth/register")
def register(x:Register,db:Session=Depends(dbdep)):
 if x.role not in ["EMPLOYEE","HR","ADMIN"]:raise HTTPException(400,"Invalid role")
 if db.query(User).filter((User.username==x.username)|(User.email==x.email)).first():raise HTTPException(409,"User exists")
 u=User(username=x.username,email=x.email,hashed_password=pwd.hash(x.password),role=x.role);db.add(u);db.commit();db.refresh(u)
 return {"token":make_token(u),"role":u.role}
@app.post("/auth/login")
def login(x:Login,db:Session=Depends(dbdep)):
 u=db.query(User).filter(User.username==x.username).first()
 if not u or not pwd.verify(x.password,u.hashed_password):raise HTTPException(401,"Invalid username or password")
 if u.status!="ACTIVE":raise HTTPException(403,"Account inactive")
 return {"token":make_token(u),"role":u.role}
@app.get("/auth/me")
def me(u=Depends(current)):return {"id":u.id,"username":u.username,"email":u.email,"role":u.role,"status":u.status}

@app.get("/self/profile")
def self_profile(db:Session=Depends(dbdep),u=Depends(current)):
 e=db.query(Employee).filter(Employee.user_id==u.id).first();return {"user":{"id":u.id,"username":u.username,"email":u.email,"role":u.role},"employee":e}
@app.get("/employees")
def employees(search:str="",db:Session=Depends(dbdep),u=Depends(roles("HR","ADMIN"))):
 q=db.query(Employee)
 if search:q=q.filter((Employee.full_name.contains(search))|(Employee.department.contains(search)))
 return q.all()
@app.post("/employees")
def add_employee(x:EmployeeIn,db:Session=Depends(dbdep),u=Depends(roles("HR","ADMIN"))):
 e=Employee(**x.model_dump());db.add(e);db.commit();db.refresh(e)
 for t,n in [("SICK",10),("CASUAL",12),("PAID",15)]:db.add(LeaveBalance(employee_id=e.id,leave_type=t,remaining_days=n))
 db.commit();return e
@app.put("/employees/{eid}")
def edit_employee(eid:int,x:EmployeeIn,db:Session=Depends(dbdep),u=Depends(roles("HR","ADMIN"))):
 e=db.get(Employee,eid)
 if not e:raise HTTPException(404,"Employee not found")
 for k,v in x.model_dump().items():setattr(e,k,v)
 db.commit();return e

@app.get("/attendance/{eid}")
def attendance(eid:int,db:Session=Depends(dbdep),u=Depends(current)):own(u,eid,db);return db.query(Attendance).filter(Attendance.employee_id==eid).order_by(Attendance.date.desc()).all()
@app.post("/attendance/check-in/{eid}")
def checkin(eid:int,db:Session=Depends(dbdep),u=Depends(current)):
 own(u,eid,db);today=date.today()
 if db.query(Attendance).filter(Attendance.employee_id==eid,Attendance.date==today).first():raise HTTPException(400,"Only one check-in per day")
 now=datetime.now();late=max(0,now.hour*60+now.minute-540);a=Attendance(employee_id=eid,date=today,check_in=now.time(),status="LATE" if late else "PRESENT",late_minutes=late);db.add(a);db.commit();db.refresh(a);return a
@app.post("/attendance/check-out/{eid}")
def checkout(eid:int,db:Session=Depends(dbdep),u=Depends(current)):
 own(u,eid,db);a=db.query(Attendance).filter(Attendance.employee_id==eid,Attendance.date==date.today()).first()
 if not a or not a.check_in:raise HTTPException(400,"Check in first")
 if a.check_out:raise HTTPException(400,"Already checked out")
 now=datetime.now();a.check_out=now.time();mins=now.hour*60+now.minute-(a.check_in.hour*60+a.check_in.minute);a.overtime_hours=max(0,(mins-480)/60);db.commit();return a

@app.get("/leaves")
def leaves(db:Session=Depends(dbdep),u=Depends(current)):
 if u.role=="EMPLOYEE":
  e=db.query(Employee).filter(Employee.user_id==u.id).first();return db.query(Leave).filter(Leave.employee_id==e.id).all() if e else []
 return db.query(Leave).all()
@app.post("/leaves")
def apply_leave(x:LeaveIn,db:Session=Depends(dbdep),u=Depends(current)):
 e=own(u,x.employee_id,db);days=(x.end_date-x.start_date).days+1;b=db.query(LeaveBalance).filter(LeaveBalance.employee_id==e.id,LeaveBalance.leave_type==x.leave_type).first()
 if x.end_date<x.start_date:raise HTTPException(400,"Invalid date range")
 if not b or b.remaining_days<days:raise HTTPException(400,"Insufficient leave balance")
 l=Leave(**x.model_dump());db.add(l);db.commit();return l
@app.patch("/leaves/{lid}/status")
def leave_status(lid:int,status:str,db:Session=Depends(dbdep),u=Depends(roles("HR","ADMIN"))):
 l=db.get(Leave,lid)
 if not l:raise HTTPException(404,"Leave not found")
 if status not in ["APPROVED","REJECTED"]:raise HTTPException(400,"Invalid status")
 if status=="APPROVED":
  days=(l.end_date-l.start_date).days+1;b=db.query(LeaveBalance).filter(LeaveBalance.employee_id==l.employee_id,LeaveBalance.leave_type==l.leave_type).first()
  if not b or b.remaining_days<days:raise HTTPException(400,"Insufficient balance")
  b.remaining_days-=days
 l.status=status;db.commit();return l
@app.get("/leave-policies")
def policies(db:Session=Depends(dbdep),u=Depends(current)):return db.query(LeavePolicy).all()
@app.post("/leave-policies")
def add_policy(x:PolicyIn,db:Session=Depends(dbdep),u=Depends(roles("ADMIN"))):
 p=LeavePolicy(**x.model_dump());db.add(p);db.commit();db.refresh(p);return p
@app.get("/leave-balances/{eid}")
def balances(eid:int,db:Session=Depends(dbdep),u=Depends(current)):own(u,eid,db);return db.query(LeaveBalance).filter(LeaveBalance.employee_id==eid).all()

@app.get("/payroll/{eid}")
def payroll(eid:int,db:Session=Depends(dbdep),u=Depends(current)):own(u,eid,db);return db.query(Payroll).filter(Payroll.employee_id==eid).order_by(Payroll.id.desc()).all()
@app.post("/payroll")
def payroll_create(x:PayrollIn,db:Session=Depends(dbdep),u=Depends(roles("HR","ADMIN"))):
 p=Payroll(**x.model_dump(),net_salary=x.basic_salary+x.allowances+x.bonus-x.deductions);db.add(p);db.commit();db.refresh(p);return p

@app.get("/admin/users")
def users(db:Session=Depends(dbdep),u=Depends(roles("ADMIN"))):return db.query(User).all()
@app.patch("/admin/users/{uid}/role")
def role(uid:int,x:RoleIn,db:Session=Depends(dbdep),u=Depends(roles("ADMIN"))):
 if x.role not in ["EMPLOYEE","HR","ADMIN"]:raise HTTPException(400,"Invalid role")
 z=db.get(User,uid);z.role=x.role;db.commit();return {"message":"Role updated"}
@app.patch("/admin/users/{uid}/status")
def status(uid:int,x:StatusIn,db:Session=Depends(dbdep),u=Depends(roles("ADMIN"))):
 if x.status not in ["ACTIVE","INACTIVE"]:raise HTTPException(400,"Invalid status")
 z=db.get(User,uid);z.status=x.status;db.commit();return {"message":"Status updated"}
@app.delete("/admin/users/{uid}")
def delete(uid:int,db:Session=Depends(dbdep),u=Depends(roles("ADMIN"))):
 z=db.get(User,uid)
 if not z:raise HTTPException(404,"User not found")
 db.delete(z);db.commit();return {"message":"User deleted"}
@app.get("/dashboard/analytics")
def analytics(db:Session=Depends(dbdep),u=Depends(roles("HR","ADMIN"))):
 return {"employees":db.query(Employee).count(),"attendance":db.query(Attendance).count(),"pending_leaves":db.query(Leave).filter(Leave.status=="PENDING").count(),"payroll_records":db.query(Payroll).count()}

def seed():
 db=SessionLocal()
 for n,e,p,r in [("admin","admin@worksphere.local","Admin@123","ADMIN"),("hr","hr@worksphere.local","Hr@123","HR"),("employee","employee@worksphere.local","Employee@123","EMPLOYEE")]:
  if not db.query(User).filter(User.username==n).first():db.add(User(username=n,email=e,hashed_password=pwd.hash(p),role=r))
 for t,n in [("SICK",10),("CASUAL",12),("PAID",15)]:
  if not db.query(LeavePolicy).filter(LeavePolicy.leave_type==t).first():db.add(LeavePolicy(leave_type=t,total_days_allowed=n))
 db.commit();db.close()
seed()
