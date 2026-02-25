import os
from urllib import response
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="DevDesperate AI Service")

HF_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
HF_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-cnn"

class SummarizeRequest(BaseModel):
    text: str

@app.get("/health")
def health():
    return {"status": "ok", "service": "ai-service"}

@app.post("/summarize")
async def summarize(request: SummarizeRequest):
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": request.text}

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(HF_URL, headers=headers, json=payload)

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail={"status_code": response.status_code, "body": response.text})
    result = response.json()
    return {"summary": result[0]["summary_text"]}
class JobMatchRequest(BaseModel):
    job_description: str
    candidate_skills: str

@app.post("/job-match")
async def job_match(request: JobMatchRequest):
    if not request.job_description.strip() or not request.candidate_skills.strip():
        raise HTTPException(status_code=400, detail="Both fields are required")

    prompt = f"""Compare this job description with the candidate skills and return a match score from 0 to 100, and a short reason why.

Job Description:
{request.job_description}

Candidate Skills:
{request.candidate_skills}

Respond in this exact JSON format:
{{"score": 75, "reason": "The candidate matches most requirements but lacks experience in X"}}"""

    HF_CLASSIFY_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt, "parameters": {"max_new_tokens": 150, "return_full_text": False}}

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(HF_CLASSIFY_URL, headers=headers, json=payload)

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="HuggingFace API error")

    result = response.json()
    return {"result": result[0]["generated_text"]}