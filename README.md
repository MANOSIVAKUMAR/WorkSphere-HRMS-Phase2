# WorkSphere HRMS – Phase 2

Includes Modules 8–13:
- RBAC with JWT role validation and ownership checks
- Employee self-service
- Advanced attendance with duplicate check-in prevention, late entry and overtime
- Leave policies and balances
- Enhanced payroll with allowances/deductions/bonus
- Admin user role/status controls
- Analytics

Backend: FastAPI, SQLAlchemy, SQLite, JWT, Pydantic.
Frontend: React, Vite, Axios.

Run backend:
```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Run frontend:
```powershell
cd frontend
npm install
npm run dev
```

Demo: admin/Admin@123, hr/Hr@123, employee/Employee@123
