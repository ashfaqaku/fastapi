from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import json

# Simple version without JWT - pehle yeh test karein
app = FastAPI()

# Simple in-memory database
users_db = {}

class UserRegister(BaseModel):
    username: str
    password: str
    email: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

# 1. Health check
@app.get("/")
def root():
    return {
        "message": "Auth API Working",
        "status": "active",
        "total_users": len(users_db)
    }

# 2. Simple register (without password hashing for now)
@app.post("/register")
def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # For testing - store plain password (temporarily)
    users_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "password": user.password,  # Temporary - don't do in production
        "hashed_password": None
    }
    
    return {
        "message": "User registered successfully",
        "username": user.username,
        "email": user.email,
        "debug_info": {
            "total_users": len(users_db),
            "users": list(users_db.keys())
        }
    }

# 3. Simple login (without password hashing for now)
@app.post("/login")
def login(user: UserLogin):
    if user.username not in users_db:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    stored_user = users_db[user.username]
    
    # Simple password check (temporary)
    if user.password != stored_user["password"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Generate simple token (for testing)
    token = f"simple_token_{user.username}_12345"
    
    return {
        "message": "Login successful",
        "username": user.username,
        "token": token,
        "token_type": "bearer"
    }

# 4. Get all users (for debugging)
@app.get("/users")
def get_users():
    users_list = []
    for username, data in users_db.items():
        users_list.append({
            "username": data["username"],
            "email": data["email"],
            "full_name": data["full_name"]
        })
    return {
        "total": len(users_list),
        "users": users_list
    }

# 5. Get user by username
@app.get("/user/{username}")
def get_user(username: str):
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_data = users_db[username].copy()
    # Remove password from response
    user_data.pop("password", None)
    user_data.pop("hashed_password", None)
    
    return user_data

# 6. Clear database (for testing)
@app.delete("/clear")
def clear_db():
    users_db.clear()
    return {"message": "Database cleared", "total_users": 0}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)