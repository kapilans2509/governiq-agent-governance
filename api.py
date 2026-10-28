import os
from typing import Literal
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from governiq_core import load_policy,evaluate,execute_demo,audit,audit_events,verify_audit

KEY=os.getenv("GOVERNIQ_API_KEY","")
app=FastAPI(title="GovernIQ Policy Gateway",version="2.0.0",description="Policy checks before registered demo tools.")
class Request(BaseModel):
 tool:str=Field(min_length=1,max_length=100)
 input:str=Field(max_length=10000)
 mode:Literal["Open","Standard","Strict","Locked"]="Standard"
 session_id:str=Field(default="demo",min_length=1,max_length=100)
 approved:bool=False
def auth(x_api_key):
 if KEY and x_api_key!=KEY: raise HTTPException(status_code=401,detail="Invalid or missing API key.")
@app.get("/health")
def health(): return {"status":"ok","service":"GovernIQ","tools":"simulated"}
@app.get("/policy")
def get_policy(x_api_key:str|None=Header(default=None)):
 auth(x_api_key); return load_policy()
@app.post("/evaluate")
def check(req:Request,x_api_key:str|None=Header(default=None)):
 auth(x_api_key)
 result=evaluate(req.tool,req.input,req.mode,calls_used=0,approval_recheck=req.approved)
 if result["decision"]=="ALLOW":
  try: result["output"]=execute_demo(req.tool,req.input)
  except PermissionError as exc: result["decision"]="DENY"; result["reason"]=str(exc)
 audit("api_response",{"session_id":req.session_id,"tool":req.tool,"decision":result["decision"]})
 return result
@app.get("/audit/verify")
def verify(x_api_key:str|None=Header(default=None)):
 auth(x_api_key); return verify_audit()
@app.get("/audit/events")
def events(limit:int=100,x_api_key:str|None=Header(default=None)):
 auth(x_api_key); return audit_events(limit)
