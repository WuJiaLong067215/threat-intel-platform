"""
认证模块 - JWT 登录/注册 + 角色权限

角色：
- admin: 管理员（全部权限）
- analyst: 安全员（查看+同步+添加资产）
- viewer: 只读用户（仅查看）
"""
import os
import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# JWT 配置
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

# 默认管理员账号（首次启动自动创建）
DEFAULT_ADMIN = {
    "username": "admin",
    "password_hash": "",  # 运行时生成
}

# 角色权限定义
ROLE_PERMISSIONS = {
    "admin": ["read", "write", "delete", "sync", "scan", "manage_users", "settings"],
    "analyst": ["read", "write", "sync", "scan"],
    "viewer": ["read"],
}


def hash_password(password: str) -> str:
    """SHA256 哈希密码"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """验证密码"""
    return hmac.compare_digest(hash_password(password), password_hash)


def create_token(username: str, role: str = "viewer") -> str:
    """生成 JWT Token"""
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """解析 JWT Token，失败返回 None"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def has_permission(role: str, permission: str) -> bool:
    """检查角色是否拥有某权限"""
    return permission in ROLE_PERMISSIONS.get(role, [])


def require_permission(permission: str):
    """
    权限检查装饰器（FastAPI Depends 用法）

    用法：
        @app.get("/api/admin/users")
        def list_users(user=Depends(require_permission("manage_users"))):
            ...
    """
    def checker(decoded=Depends(get_current_user)):
        if not has_permission(decoded.get("role", "viewer"), permission):
            raise HTTPException(status_code=403, detail="权限不足")
        return decoded
    return checker


# ── 数据库操作 ──

def get_user_collection():
    from database.db_manager import get_db
    return get_db()["users"]


def init_default_admin():
    """初始化默认管理员（admin/admin123）"""
    col = get_user_collection()
    if col.find_one({"username": "admin"}) is None:
        col.insert_one({
            "username": "admin",
            "password_hash": hash_password("admin123"),
            "role": "admin",
            "department": "",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": None,
        })
        logger.info("✅ 默认管理员已创建: admin / admin123")


def register_user(username: str, password: str, role: str = "viewer", department: str = ""):
    """注册用户"""
    col = get_user_collection()
    if col.find_one({"username": username}):
        return None, "用户名已存在"
    if role not in ROLE_PERMISSIONS:
        return None, f"无效角色: {role}，可选: {list(ROLE_PERMISSIONS.keys())}"
    col.insert_one({
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "department": department,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login": None,
    })
    logger.info(f"✅ 用户注册: {username} ({role})")
    return {"username": username, "role": role}, None


def authenticate(username: str, password: str):
    """用户认证，成功返回 (token, user_info)"""
    col = get_user_collection()
    user = col.find_one({"username": username})
    if not user or not verify_password(password, user["password_hash"]):
        return None, "用户名或密码错误"

    token = create_token(username, user["role"])
    # 更新登录时间
    col.update_one({"username": username}, {"$set": {"last_login": datetime.now(timezone.utc).isoformat()}})

    return {
        "token": token,
        "token_type": "Bearer",
        "expires_in": JWT_EXPIRE_HOURS * 3600,
        "user": {
            "username": user["username"],
            "role": user["role"],
            "department": user.get("department", ""),
        }
    }, None


def list_users():
    """列出所有用户"""
    col = get_user_collection()
    users = []
    for u in col.find({}, {"password_hash": 0, "_id": 0}):
        users.append(u)
    return users


def delete_user(username: str):
    """删除用户（不能删 admin）"""
    if username == "admin":
        return False, "不能删除管理员"
    col = get_user_collection()
    result = col.delete_one({"username": username})
    if result.deleted_count == 0:
        return False, "用户不存在"
    return True, None


def change_password(username: str, old_password: str, new_password: str):
    """修改密码"""
    col = get_user_collection()
    user = col.find_one({"username": username})
    if not user or not verify_password(old_password, user["password_hash"]):
        return False, "原密码错误"
    col.update_one({"username": username}, {"$set": {"password_hash": hash_password(new_password)}})
    return True, None


# ── FastAPI 依赖 ──

from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """获取当前登录用户"""
    if credentials is None:
        raise HTTPException(status_code=401, detail="未登录，请先认证")
    decoded = decode_token(credentials.credentials)
    if decoded is None:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")
    return decoded


async def get_optional_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """可选认证（登录了就有用户信息，没登录也不报错）"""
    if credentials is None:
        return {"role": "viewer", "sub": "anonymous"}
    decoded = decode_token(credentials.credentials)
    if decoded is None:
        return {"role": "viewer", "sub": "anonymous"}
    return decoded
