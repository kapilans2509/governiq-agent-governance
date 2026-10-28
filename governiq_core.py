import hashlib, json, re, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent
POLICY_FILE = ROOT / "governance_policy.json"
DB_FILE = ROOT / "data" / "audit.db"
DEFAULT_POLICY = {
 "name":"GovernIQ baseline","version":"2.0.0",
 "allowed_tools":["search_policy","read_status","draft_report"],
 "blocked_tools":["shell_exec","delete_database","send_external_data"],
 "require_human_approval":["draft_report"],"max_calls_per_session":10,"max_input_chars":4000,
 "governance_modes":{
  "Open":{"block_threats":False,"require_approval_for_all":False},
  "Standard":{"block_threats":True,"require_approval_for_all":False},
  "Strict":{"block_threats":True,"require_approval_for_all":True},
  "Locked":{"block_threats":True,"require_approval_for_all":True}},
 "blocked_patterns":[r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
  r"\b(api[_ -]?key|password|secret)\s*[:=]\s*\S+",
  r"\b(drop\s+database|truncate\s+table|rm\s+-rf)\b"]
}


THREATS = [
    (
        "prompt_injection",
        "Instruction-override phrase",
        r"(?i)\b(?:ignore|disregard|forget)\b.{0,60}\b(?:previous|prior|above|earlier|system)\b.{0,40}\binstructions\b",
 
    ),
    (
        "role_impersonation",
        "Attempt to assume or claim a privileged role",
        r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|i\s+am|i'm)\s+(?:the\s+)?(?:system\s+administrator|administrator|admin|system|developer|root)\b",
    ),
    (
        "safeguard_override",
        "Attempt to bypass safeguards",
        r"(?i)\b(?:override|bypass|disable|ignore|disregard)\b.{0,100}\b(?:restrictions|safeguards|security\s+rules|policies|guardrails|governance\s+enforcement)\b",
    ),
    (
        "confidential_data_request",
        "Request to disclose confidential information",
        r"(?i)\b(?:reveal|show|disclose|print|expose|dump|return)\b.{0,80}\b(?:confidential|secret|private|hidden|internal)\b.{0,40}\b(?:data|information|instructions|records|content|configuration|system\s+prompt|governance\s+rules)\b",
    ),
    (
        "credential_exposure",
        "Credential-like key/value",
        r"(?i)\b(?:api[_ -]?key|password|secret|token)\s*[:=]\s*\S+",
    ),
    (
        "data_exfiltration",
        "Possible external bulk transfer",
        r"(?i)\b(?:send|export|upload|transfer)\s+(?:all|every|entire)\s+.{0,100}\b(?:external|outside|third.party)\b",
    ),
    (
        "destructive_action",
        "Destructive command",
        r"(?i)\b(?:rm\s+-rf|drop\s+database|truncate\s+table|format\s+c:)\b",
    ),
    (
        "privilege_escalation",
        "Privilege escalation",
        r"(?i)\b(?:sudo|as\s+root|chmod\s+777|grant\s+admin|disable\s+(?:the\s+)?governance\s+enforcement)\b",
    ),
]

def load_policy():
 if not POLICY_FILE.exists(): POLICY_FILE.write_text(json.dumps(DEFAULT_POLICY,indent=2),encoding="utf-8")
 p=json.loads(POLICY_FILE.read_text(encoding="utf-8"))
 required=set(DEFAULT_POLICY)
 if not required.issubset(p): raise ValueError(f"Policy missing: {sorted(required-set(p))}")
 if not isinstance(p["max_input_chars"],int) or p["max_input_chars"]<1: raise ValueError("Invalid max_input_chars")
 if not isinstance(p["max_calls_per_session"],int) or p["max_calls_per_session"]<1: raise ValueError("Invalid session limit")
 return p
def now(): return datetime.now(timezone.utc).isoformat()
def db():
 DB_FILE.parent.mkdir(parents=True,exist_ok=True)
 c=sqlite3.connect(DB_FILE,timeout=10); c.row_factory=sqlite3.Row
 c.execute("""CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,event_id TEXT UNIQUE,timestamp TEXT,event TEXT,payload TEXT,previous_hash TEXT,event_hash TEXT)""")
 c.commit(); return c
def audit(event,payload):
 c=db()
 try:
  last=c.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
  prev=last["event_hash"] if last else "GENESIS"
  rec={"event_id":str(uuid.uuid4()),"timestamp":now(),"event":event,"payload":payload,"previous_hash":prev}
  canonical=json.dumps(rec,sort_keys=True,separators=(",",":"),ensure_ascii=False)
  digest=hashlib.sha256(canonical.encode()).hexdigest()
  c.execute("INSERT INTO audit(event_id,timestamp,event,payload,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
   (rec["event_id"],rec["timestamp"],event,json.dumps(payload,sort_keys=True,ensure_ascii=False),prev,digest))
  c.commit(); return {**rec,"event_hash":digest}
 finally: c.close()
def audit_events(limit=500):
 c=db()
 try:
  rows=c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?",(max(1,min(limit,5000)),)).fetchall()
  return [{"id":r["id"],"event_id":r["event_id"],"timestamp":r["timestamp"],"event":r["event"],
   "payload":json.loads(r["payload"]),"previous_hash":r["previous_hash"],"event_hash":r["event_hash"]} for r in rows]
 finally: c.close()
def verify_audit():
 c=db()
 try:
  rows=c.execute("SELECT * FROM audit ORDER BY id").fetchall(); prev="GENESIS"
  for n,r in enumerate(rows):
   rec={"event_id":r["event_id"],"timestamp":r["timestamp"],"event":r["event"],
    "payload":json.loads(r["payload"]),"previous_hash":r["previous_hash"]}
   digest=hashlib.sha256(json.dumps(rec,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
   if r["previous_hash"]!=prev or r["event_hash"]!=digest:
    return {"valid":False,"checked":n,"failed_id":r["event_id"]}
   prev=r["event_hash"]
  return {"valid":True,"checked":len(rows)}
 finally: c.close()
def detect(text):
 found=[]
 for sid,label,pattern in THREATS:
  m=re.search(pattern,text)
  if m: found.append({"signal_id":sid,"description":label,"matched_text":m.group(0)[:120]})
 return found
def evaluate(tool,text,mode="Standard",calls_used=0,approval_recheck=False):
 p=load_policy(); mode=mode if mode in p["governance_modes"] else "Standard"
 cfg=p["governance_modes"][mode]; threats=detect(text)
 if len(text)>p["max_input_chars"]: d,r="DENY","Input exceeds maximum length."
 elif calls_used>=p["max_calls_per_session"]: d,r="DENY","Session call limit reached."
 elif tool in p["blocked_tools"]: d,r="DENY",f"Tool '{tool}' is explicitly blocked."
 elif tool not in p["allowed_tools"]: d,r="DENY",f"Tool '{tool}' is not allowlisted."
 elif threats and cfg["block_threats"]: d,r="DENY",f"Threat signal detected: {threats[0]['signal_id']}."
 elif cfg["block_threats"] and any(re.search(x,text,re.I) for x in p["blocked_patterns"]): d,r="DENY","Configured blocked pattern matched."
 elif (tool in p["require_human_approval"] or cfg["require_approval_for_all"]) and not approval_recheck: d,r="REVIEW",f"Human approval required for '{tool}'."
 else: d,r="ALLOW","Policy checks passed."
 result={"decision":d,"reason":r,"tool":tool,"mode":mode,"threats":threats,"policy_version":p["version"],"evaluated_at":now()}
 audit("request_evaluated",{**result,"input_preview":text[:160]})
 return result
def execute_demo(tool,text):
 p=load_policy()
 if tool not in p["allowed_tools"] or tool in p["blocked_tools"]: raise PermissionError("No permitted demo adapter for this tool.")
 if tool=="search_policy":
  items=[{"control":"Least privilege","description":"Allow only tools required for the task."},{"control":"Human approval","description":"Require approval for consequential actions."},{"control":"Auditability","description":"Record decisions and outcomes."},{"control":"Data protection","description":"Protect credentials and control data transfers."}]
  q=text.lower(); out={"results":[x for x in items if q in json.dumps(x).lower()] or items,"simulated":True}
 elif tool=="read_status": out={"status":"operational","environment":"simulation","simulated":True}
 elif tool=="draft_report": out={"draft":f"GOVERNANCE REVIEW — DRAFT\n\nRequest: {text}\n\nReview permissions, threat signals, approvals, rate limits and audit evidence. Verify before use.","simulated":True}
 else: raise PermissionError("No adapter registered.")
 audit("simulated_tool_executed",{"tool":tool,"outcome":"success"})
 return out
