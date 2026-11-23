import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.defense_core import Event, EventBus, Evidence, Finding, ActionPolicy, DetectionRule, DetectionEngine

class DefensiveCoreTests(unittest.TestCase):
 def test_event_validation_and_bounded_history(self):
  bus=EventBus(2); events=[Event("proc.start","test",{"pid":1}),Event("proc.start","test",{"pid":2}),Event("proc.start","test",{"pid":3})]
  for e in events: bus.publish(e)
  self.assertEqual([e.data["pid"] for e in bus.history()], [2,3])
  with self.assertRaises(TypeError): bus.publish({})
 def test_subscriber_failure_is_isolated(self):
  bus=EventBus(); seen=[]; bus.subscribe(lambda e: (_ for _ in ()).throw(RuntimeError())) ; bus.subscribe(lambda e: seen.append(e.event_id))
  e=Event("x","source",{}); bus.publish(e); self.assertEqual(seen,[e.event_id]); self.assertEqual(bus.subscriber_errors,["RuntimeError"])
 def test_policy_default_deny_and_approval(self):
  p=ActionPolicy(); self.assertTrue(p.evaluate("inspect_posture").allowed); self.assertFalse(p.evaluate("shell").allowed)
  d=p.evaluate("terminate_process"); self.assertFalse(d.allowed); self.assertTrue(d.requires_approval)
  self.assertTrue(p.evaluate("terminate_process",approval_granted=True).allowed)
 def test_detection_produces_evidence_finding(self):
  engine=DetectionEngine([DetectionRule("R1","Encoded process","process.start",{"encoded":True},"high",0.9)])
  result=engine.process(Event("process.start","collector",{"encoded":True,"pid":42}))
  self.assertEqual(len(result),1); self.assertEqual(result[0].severity,"high"); self.assertEqual(result[0].evidence[0].source,"collector")
  self.assertEqual(engine.process(Event("process.start","collector",{"encoded":False})),[])
 def test_finding_requires_evidence_and_valid_confidence(self):
  with self.assertRaises(ValueError): Finding("R","title","high",0.8,())
  with self.assertRaises(ValueError): Finding("R","title","high",1.1,(Evidence("e","summary","source"),))
 def test_bus_attachment_emits_findings(self):\n  bus=EventBus(); engine=DetectionEngine([DetectionRule(\"R\",\"title\",\"x\",{})]); engine.attach(bus); bus.publish(Event(\"x\",\"source\",{})); self.assertEqual(len(engine.findings),1)\n def test_duplicate_rule_rejected(self):
  e=DetectionEngine(); r=DetectionRule("R","title","type",{}); e.add_rule(r)
  with self.assertRaises(ValueError): e.add_rule(r)
if __name__ == "__main__": unittest.main()
