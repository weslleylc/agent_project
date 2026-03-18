from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn
import os

load_dotenv()

import level1
import level2
import level3
import level4

app = FastAPI(title="AI Agent CTF")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(level1.router, prefix="/level1")
app.include_router(level2.router, prefix="/level2")
app.include_router(level3.router, prefix="/level3")
app.include_router(level4.router, prefix="/level4")

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    with open("templates/index.html") as f:
        return f.read()


@app.get("/play/{level}", response_class=HTMLResponse)
async def play(level: int):
    with open(f"templates/level{level}.html") as f:
        return f.read()


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
