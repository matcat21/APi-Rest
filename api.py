from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

# === CONFIGURACIÓN ===
SECRET_KEY = "tu_clave_secreta_super_segura"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# === MODELOS DE DATOS ===
class UserRegister(BaseModel):
    user: str
    pwd: str
    email: EmailStr
    rol: str = "Usuario"  # Por defecto


class UserLogin(BaseModel):
    user: str
    pwd: str


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str


class OrchestrateRequest(BaseModel):
    servicio_destino: str
    parametros_adicionales: Dict


class ServiceInfo(BaseModel):
    id: str
    nombre: str
    descripcion: str
    endpoints: List[str]


class RegisterService(BaseModel):
    nombre: str
    descripcion: str
    endpoints: List[str]


class UpdateRulesRequest(BaseModel):
    reglas: Dict


class AuthorizeRequest(BaseModel):
    recursos: List[str]
    rol_usuario: str


# === BASE DE DATOS SIMULADA ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
usuarios_db = {}  # Usuarios registrados
servicios_db = {}  # Servicios registrados


# === FUNCIONES DE SEGURIDAD ===
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str):
    return usuarios_db.get(username)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# === AUTENTICACIÓN ===
app = FastAPI(title="API Completa - Logística Global", version="1.0.0")


@app.post("/registro")
def register(payload: UserRegister):
    if payload.user in usuarios_db:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    hashed_pwd = pwd_context.hash(payload.pwd)
    usuarios_db[payload.user] = {
        "user": payload.user,
        "pwd": hashed_pwd,
        "email": payload.email,
        "rol": payload.rol
    }

    return {"mensaje": f"Usuario '{payload.user}' registrado exitosamente", "rol": payload.rol}


@app.post("/login", response_model=Token)
def login(payload: UserLogin):
    user_record = get_user(payload.user)

    if not user_record or not verify_password(payload.pwd, user_record.get("pwd")):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": payload.user, "rol": user_record["rol"]},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user_record["rol"]
    }


# === MIDDLEWARE PARA VERIFICAR TOKEN ===
def get_current_user(token: str = Depends(lambda x: x.headers.get("authorization"))):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if not token or not token.startswith("Bearer "):
            raise credentials_exception
        token = token.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


# === ENDPOINTS PROTEGIDOS ===
@app.post("/orquestar")
def orchestrate(payload: OrchestrateRequest, claims: dict = Depends(get_current_user)):
    allowed_roles = ["Orquestador", "Administrador"]
    if claims.get("rol") not in allowed_roles:
        raise HTTPException(status_code=403, detail="Acceso denegado")

    return {
        "mensaje": f"Servicio '{payload.servicio_destino}' orquestado correctamente.",
        "parametros": payload.parametros_adicionales,
        "usuario": claims.get("sub"),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/servicio/{id}")
def get_service(id: str, claims: dict = Depends(get_current_user)):
    if id not in servicios_db:
        raise HTTPException(status_code=404, detail="Servicio no encontrado")
    return servicios_db[id]


@app.post("/registrar-servicio")
def register_service(payload: RegisterService, claims: dict = Depends(get_current_user)):
    if claims.get("rol") != "Administrador":
        raise HTTPException(status_code=403, detail="Acceso denegado")

    service_id = str(len(servicios_db) + 1)
    servicios_db[service_id] = {
        "id": service_id,
        "nombre": payload.nombre,
        "descripcion": payload.descripcion,
        "endpoints": payload.endpoints
    }

    return {"mensaje": "Servicio registrado exitosamente", "id": service_id}


@app.put("/actualizar-reglas-orquestacion")
def update_orchestration_rules(payload: UpdateRulesRequest, claims: dict = Depends(get_current_user)):
    if claims.get("rol") != "Orquestador":
        raise HTTPException(status_code=403, detail="Acceso denegado")

    return {
        "mensaje": "Reglas de orquestación actualizadas",
        "reglas": payload.reglas,
        "usuario": claims.get("sub"),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/autorizar-acceso")
def authorize_access(payload: AuthorizeRequest, claims: dict = Depends(get_current_user)):
    allowed_resources = {
        "Administrador": ["/registrar-servicio"],
        "Orquestador": ["/orquestar", "/actualizar-reglas-orquestacion"]
    }

    denied = []
    for recurso in payload.recursos:
        owner_role = next((r for r, res in allowed_resources.items() if recurso in res), None)
        if owner_role and owner_role != payload.rol_usuario:
            denied.append(recurso)

    return {
        "acceso_permitido": len(denied) == 0,
        "rechazados": denied
    }