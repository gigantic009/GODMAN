"""Evidence-linked defensive findings; conclusions remain explainable."""
from dataclasses import dataclass,field
from datetime import datetime,timezone
import uuid
@dataclass(frozen=True)
class Evidence:
 event_id:str
 summary:str
 source:str
 observed_at:str=field(default_factory=lambda:datetime.now(timezone.utc).isoformat())
 def __post_init__(self):
  if not self.event_id or not self.summary or not self.source: raise ValueError("evidence fields must be non-empty")
  if len(self.summary)>1000: raise ValueError("evidence summary is too long")
@dataclass(frozen=True)
class Finding:
 rule_id:str
 title:str
 severity:str
 confidence:float
 evidence:tuple[Evidence,...]
 description:str=""
 finding_id:str=field(default_factory=lambda:str(uuid.uuid4()))
 created_at:str=field(default_factory=lambda:datetime.now(timezone.utc).isoformat())
 status:str="open"
 def __post_init__(self):
  if self.severity not in {"info","low","medium","high","critical"}: raise ValueError("invalid severity")
  if isinstance(self.confidence,bool) or not isinstance(self.confidence,(int,float)) or not 0<=self.confidence<=1: raise ValueError("confidence must be between 0 and 1")
  if not self.rule_id or not self.title: raise ValueError("rule_id and title are required")
  if not self.evidence: raise ValueError("findings require evidence")
  if self.status not in {"open","acknowledged","resolved","false_positive"}: raise ValueError("invalid status")
