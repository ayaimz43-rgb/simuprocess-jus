import hashlib
import secrets
import sqlite3
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="SimuProcess - Concentration de Jus")
templates = Jinja2Templates(directory="templates")
DB_PATH = "dusedp.db"

# Sessions simples en mémoire (suffisant en local)
SESSIONS: dict[str, dict] = {}


def hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return secrets.compare_digest(hash_password(password, salt), stored)


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                m0 REAL NOT NULL,
                x0 REAL NOT NULL,
                residus REAL NOT NULL,
                mR REAL NOT NULL,
                xR REAL NOT NULL,
                Cp REAL NOT NULL,
                T2 REAL NOT NULL,
                T3 REAL NOT NULL,
                x4 REAL NOT NULL,
                lambda_v REAL NOT NULL,
                T4 REAL NOT NULL,
                T5 REAL NOT NULL,
                m1 REAL NOT NULL,
                x1 REAL NOT NULL,
                m2 REAL NOT NULL,
                x2 REAL NOT NULL,
                Q3 REAL NOT NULL,
                m4 REAL NOT NULL,
                mv REAL NOT NULL,
                Q4 REAL NOT NULL,
                Q5 REAL NOT NULL
            )
        """)
        # Ajout de la colonne user_id si l'ancienne table existait déjà
        try:
            conn.execute("ALTER TABLE simulations ADD COLUMN user_id INTEGER")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def get_current_user(request: Request) -> dict | None:
    token = request.cookies.get("session_token")
    if not token:
        return None
    return SESSIONS.get(token)


def calculer_procede(
    m0: float,
    x0: float,
    residus: float,
    mR: float,
    xR: float,
    Cp: float,
    T2: float,
    T3: float,
    x4: float,
    lambda_v: float,
    T4: float,
    T5: float,
) -> dict:
    if m0 <= 0 or m0 - residus <= 0 or x4 <= 0:
        raise ValueError("Vérifiez les débits et concentrations (valeurs positives requises).")

    m1 = m0 - residus
    x1 = (m0 * x0) / m1

    m2 = m1 + mR
    x2 = (m1 * x1 + mR * xR) / m2

    Q3 = m2 * Cp * (T3 - T2) / 3600

    m4 = m2 * x2 / x4
    mv = m2 - m4
    Q4 = mv * lambda_v / 3600

    Q5 = m4 * Cp * (T4 - T5) / 3600

    return {
        "m1": round(m1, 2),
        "x1": round(x1, 4),
        "m2": round(m2, 2),
        "x2": round(x2, 4),
        "x2_pct": round(x2 * 100, 2),
        "Q3": round(Q3, 2),
        "m4": round(m4, 2),
        "mv": round(mv, 2),
        "Q4": round(Q4, 2),
        "Q5": round(Q5, 2),
    }


def get_historique(user_id: int) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, m0, x0, residus, mR, xR, x4, m1, x1, m2, x2, Q3, m4, mv, Q4, Q5
            FROM simulations
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


@app.on_event("startup")
def startup():
    init_db()


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html", context={"error": None})


@app.post("/register", response_class=HTMLResponse)
def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    username = username.strip()
    email = email.strip().lower()
    if not username or not email or len(password) < 4:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Remplissez tous les champs (mot de passe ≥ 4 caractères)."},
        )

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hash_password(password)),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Cet email est déjà utilisé."},
        )

    return RedirectResponse(url="/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    email = email.strip().lower()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Email ou mot de passe incorrect."},
        )

    token = secrets.token_urlsafe(24)
    SESSIONS[token] = {"id": user["id"], "username": user["username"], "email": user["email"]}
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="session_token", value=token, httponly=True)
    return response


@app.get("/logout")
def logout(request: Request):
    token = request.cookies.get("session_token")
    if token:
        SESSIONS.pop(token, None)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session_token")
    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    defaults = {
        "m0": 1000.0,
        "x0": 0.10,
        "residus": 20.0,
        "mR": 100.0,
        "xR": 0.40,
        "Cp": 3.8,
        "T2": 20.0,
        "T3": 80.0,
        "x4": 0.40,
        "lambda_v": 2300.0,
        "T4": 80.0,
        "T5": 25.0,
    }
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": user,
            "inputs": defaults,
            "res": None,
            "error": None,
            "historique": get_historique(user["id"]),
        },
    )


@app.post("/calculer", response_class=HTMLResponse)
def calculer(
    request: Request,
    m0: float = Form(...),
    x0: float = Form(...),
    residus: float = Form(...),
    mR: float = Form(...),
    xR: float = Form(...),
    Cp: float = Form(...),
    T2: float = Form(...),
    T3: float = Form(...),
    x4: float = Form(...),
    lambda_v: float = Form(...),
    T4: float = Form(...),
    T5: float = Form(...),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    inputs = {
        "m0": m0, "x0": x0, "residus": residus, "mR": mR, "xR": xR,
        "Cp": Cp, "T2": T2, "T3": T3, "x4": x4, "lambda_v": lambda_v,
        "T4": T4, "T5": T5,
    }

    try:
        res = calculer_procede(m0, x0, residus, mR, xR, Cp, T2, T3, x4, lambda_v, T4, T5)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "user": user,
                "inputs": inputs,
                "res": None,
                "error": str(e),
                "historique": get_historique(user["id"]),
            },
        )

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO simulations (
                user_id, m0, x0, residus, mR, xR, Cp, T2, T3, x4, lambda_v, T4, T5,
                m1, x1, m2, x2, Q3, m4, mv, Q4, Q5
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"], m0, x0, residus, mR, xR, Cp, T2, T3, x4, lambda_v, T4, T5,
                res["m1"], res["x1"], res["m2"], res["x2"],
                res["Q3"], res["m4"], res["mv"], res["Q4"], res["Q5"],
            ),
        )
        conn.commit()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": user,
            "inputs": inputs,
            "res": res,
            "error": None,
            "historique": get_historique(user["id"]),
        },
    )