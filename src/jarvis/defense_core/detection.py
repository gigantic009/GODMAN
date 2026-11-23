"""Deterministic, testable event-to-finding detection rules."""
from dataclasses import dataclass
from typing import Any
from .events import Event
from .findings import Finding,Evidence
@dataclass(frozen=True)
class DetectionRule:
 rule_id:str
 title:str
 event_type:str
 field_equals:dict[str,Any]
 severity:str="medium"
 confidence:float=0.7
 description:str=""
 def __post_init__(self):
  if not self.rule_id or not self.title or not self.event_type: raise ValueError("rule identity fields required")
  if self.severity not in {"info","low","medium","high","critical"}: raise ValueError("invalid severity")
  if isinstance(self.confidence,bool) or not isinstance(self.confidence,(int,float)) or not 0<=self.confidence<=1: raise ValueError("invalid confidence")
  if len(self.field_equals)>50: raise ValueError("rule has too many conditions")
class DetectionEngine:
 def __init__(self,rules=()):
  self.rules=[]
  for rule in rules:self.add_rule(rule)
 def add_rule(self,rule):
  if not isinstance(rule,DetectionRule):raise TypeError("rule must be a DetectionRule")
  if any(x.rule_id==rule.rule_id for x in self.rules):raise ValueError("duplicate rule ID")
  self.rules.append(rule)
 def process(self,event:Event)->list[Finding]:
  findings=[]
  for rule in self.rules:
   if rule.event_type!=event.event_type:continue
   if all(event.data.get(k)==v for k,v in rule.field_equals.items()):
    evidence=Evidence(event_id=event.event_id,summary=f"Event matched detection rule {rule.rule_id}",source=event.source)
    findings.append(Finding(rule_id=rule.rule_id,title=rule.title,severity=rule.severity,confidence=rule.confidence,evidence=(evidence,),description=rule.description))
  return findings
