import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents

# App and CORS
app = FastAPI(title="Personal Finance Manager API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Utility
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def hash_password(password: str) -> str:
    # bcrypt supports up to 72 bytes; truncate to avoid backend errors
    if isinstance(password, str):
        password = password.encode("utf-8")
    password = password[:72]
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    if isinstance(password, str):
        password = password.encode("utf-8")
    password = password[:72]
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() != "bearer":
            raise ValueError("Invalid scheme")
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["id"] = str(user["_id"])  # normalize
        user.pop("_id")
        return user
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")


# Models
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=6)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TransactionIn(BaseModel):
    type: Literal["income", "expense"]
    amount: float = Field(gt=0)
    category: str
    date: datetime
    note: Optional[str] = None


class TransactionOut(TransactionIn):
    id: str


class GoalIn(BaseModel):
    name: str
    target_amount: float = Field(gt=0)
    current_amount: float = 0
    deadline: Optional[datetime] = None


class GoalOut(GoalIn):
    id: str
    achieved: bool = False


@app.get("/")
def root():
    return {"message": "Personal Finance Manager API"}


@app.get("/test")
def test_database():
    from database import db as _db
    return {
        "backend": "✅ Running",
        "database": "✅ Connected" if _db is not None else "❌ Not Available",
        "collections": list(_db.list_collection_names()) if _db else [],
    }


# Auth routes
@app.post("/auth/register", response_model=Token)
def register(req: RegisterRequest):
    existing = db["user"].find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": req.name,
        "email": req.email,
        "hashed_password": hash_password(req.password),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    inserted_id = db["user"].insert_one(user_doc).inserted_id
    token = create_access_token({"sub": str(inserted_id)})
    return Token(access_token=token)


@app.post("/auth/login", response_model=Token)
def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email})
    if not user or not verify_password(req.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=token)


@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    return {"user": user}


# Transactions
@app.post("/transactions", response_model=TransactionOut)
def create_transaction(payload: TransactionIn, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({
        "user_id": str(user["id"]),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    result = db["transaction"].insert_one(doc)
    doc["id"] = str(result.inserted_id)
    return TransactionOut(**{**payload.model_dump(), "id": doc["id"]})


@app.get("/transactions", response_model=List[TransactionOut])
def list_transactions(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    type: Optional[str] = None,
    category: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    query: dict[str, Any] = {"user_id": str(user["id"])}
    if type:
        query["type"] = type
    if category:
        query["category"] = category
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    items = list(db["transaction"].find(query).sort("date", 1))
    return [
        TransactionOut(
            id=str(it["_id"]),
            type=it["type"],
            amount=float(it["amount"]),
            category=it["category"],
            date=it["date"],
            note=it.get("note"),
        )
        for it in items
    ]


@app.delete("/transactions/{tx_id}")
def delete_transaction(tx_id: str, user: dict = Depends(get_current_user)):
    res = db["transaction"].delete_one({"_id": ObjectId(tx_id), "user_id": str(user["id"])})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return {"ok": True}


# Goals
@app.post("/goals", response_model=GoalOut)
def create_goal(payload: GoalIn, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({
        "user_id": str(user["id"]),
        "achieved": doc.get("current_amount", 0) >= doc["target_amount"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    result = db["goal"].insert_one(doc)
    return GoalOut(**payload.model_dump(), id=str(result.inserted_id), achieved=doc["achieved"])


@app.get("/goals", response_model=List[GoalOut])
def list_goals(user: dict = Depends(get_current_user)):
    items = list(db["goal"].find({"user_id": str(user["id"])}) )
    return [
        GoalOut(
            id=str(it["_id"]),
            name=it["name"],
            target_amount=float(it["target_amount"]),
            current_amount=float(it.get("current_amount", 0)),
            deadline=it.get("deadline"),
            achieved=bool(it.get("achieved", False)),
        )
        for it in items
    ]


@app.patch("/goals/{goal_id}", response_model=GoalOut)
def update_goal(goal_id: str, payload: GoalIn, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc["updated_at"] = datetime.now(timezone.utc)
    doc["achieved"] = doc.get("current_amount", 0) >= doc["target_amount"]
    res = db["goal"].find_one_and_update(
        {"_id": ObjectId(goal_id), "user_id": str(user["id"])},
        {"$set": doc},
        return_document=True,
    )
    if not res:
        raise HTTPException(status_code=404, detail="Goal not found")
    return GoalOut(
        id=str(res["_id"]),
        name=res["name"],
        target_amount=float(res["target_amount"]),
        current_amount=float(res.get("current_amount", 0)),
        deadline=res.get("deadline"),
        achieved=bool(res.get("achieved", False)),
    )


@app.delete("/goals/{goal_id}")
def delete_goal(goal_id: str, user: dict = Depends(get_current_user)):
    res = db["goal"].delete_one({"_id": ObjectId(goal_id), "user_id": str(user["id"])})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Goal not found")
    return {"ok": True}


# Stats and reports
class SummaryResponse(BaseModel):
    income: float
    expenses: float
    savings: float
    monthly: list
    by_category: list


@app.get("/stats/summary", response_model=SummaryResponse)
def summary(user: dict = Depends(get_current_user)):
    user_id = str(user["id"]) if isinstance(user["id"], (str,)) else user["id"]
    pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": "$type",
            "total": {"$sum": "$amount"}
        }}
    ]
    sums = {d["_id"]: d["total"] for d in db["transaction"].aggregate(pipeline)}
    income = float(sums.get("income", 0))
    expenses = float(sums.get("expense", 0))
    savings = income - expenses

    # Monthly breakdown (last 6 months)
    six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)
    monthly_pipe = [
        {"$match": {"user_id": user_id, "date": {"$gte": six_months_ago}}},
        {"$group": {
            "_id": {"y": {"$year": "$date"}, "m": {"$month": "$date"}, "t": "$type"},
            "total": {"$sum": "$amount"}
        }},
        {"$sort": {"_id.y": 1, "_id.m": 1}}
    ]
    monthly_raw = list(db["transaction"].aggregate(monthly_pipe))
    # shape into [{month: '2025-01', income: X, expense: Y}]
    monthly_dict = {}
    for d in monthly_raw:
        key = f"{int(d['_id']['y']):04d}-{int(d['_id']['m']):02d}"
        if key not in monthly_dict:
            monthly_dict[key] = {"month": key, "income": 0.0, "expense": 0.0}
        monthly_dict[key][d["_id"]["t"]] = float(d["total"])
    monthly = list(monthly_dict.values())

    # By category (expenses only)
    cat_pipe = [
        {"$match": {"user_id": user_id, "type": "expense"}},
        {"$group": {"_id": "$category", "total": {"$sum": "$amount"}}},
        {"$sort": {"total": -1}},
        {"$limit": 10},
    ]
    by_category = [{"category": d["_id"], "total": float(d["total"]) } for d in db["transaction"].aggregate(cat_pipe)]

    return SummaryResponse(income=income, expenses=expenses, savings=savings, monthly=monthly, by_category=by_category)


# CSV import/export
class CSVImportRequest(BaseModel):
    rows: List[dict]


@app.post("/transactions/import")
def import_csv(req: CSVImportRequest, user: dict = Depends(get_current_user)):
    inserted = 0
    for row in req.rows:
        try:
            doc = {
                "user_id": str(user["id"]),
                "type": str(row.get("type", "")).lower(),
                "amount": float(row.get("amount")),
                "category": row.get("category", "other"),
                "date": datetime.fromisoformat(row.get("date")),
                "note": row.get("note"),
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
            if doc["type"] not in ("income", "expense"):
                continue
            db["transaction"].insert_one(doc)
            inserted += 1
        except Exception:
            continue
    return {"inserted": inserted}


@app.get("/transactions/export")
def export_csv(user: dict = Depends(get_current_user)):
    import csv
    from io import StringIO

    items = list(db["transaction"].find({"user_id": str(user["id"]) }).sort("date", 1))
    f = StringIO()
    writer = csv.writer(f)
    writer.writerow(["type", "amount", "category", "date", "note"]) 
    for it in items:
        writer.writerow([it["type"], it["amount"], it["category"], it["date"].isoformat(), it.get("note", "")])
    return {"csv": f.getvalue()}


# PDF report (simple summary)
@app.get("/reports/summary.pdf")
def pdf_report(user: dict = Depends(get_current_user)):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from io import BytesIO
    from fastapi.responses import Response

    sums = summary(user)  # reuse

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 18)
    c.drawString(72, height - 72, "Resumen Financiero")
    c.setFont("Helvetica", 12)
    c.drawString(72, height - 110, f"Ingresos: ${sums.income:,.2f}")
    c.drawString(72, height - 130, f"Gastos: ${sums.expenses:,.2f}")
    c.drawString(72, height - 150, f"Ahorro Neto: ${sums.savings:,.2f}")
    c.drawString(72, height - 190, f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')} ")
    c.showPage()
    c.save()
    pdf = buffer.getvalue()
    buffer.close()
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=summary.pdf"})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
