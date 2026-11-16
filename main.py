
from fastapi import FastAPI
from routers.auth import router as auth_router


app = FastAPI(title="E-Commerce Backend")

app.include_router(auth_router)


@app.get("/")
def home():
    return {"message": "E-Commerce Backend is running"}
