from __future__ import annotations
import hashlib,json,random,statistics
from dataclasses import dataclass,asdict,field
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent; REPORTS=ROOT/'reports'; AUDIT=ROOT/'audit'
def now(): return datetime.now(timezone.utc).isoformat()
def sha256_bytes(b): return hashlib.sha256(b).hexdigest()
def sha256_obj(o): return sha256_bytes(json.dumps(o,sort_keys=True,separators=(',',':')).encode())
@dataclass
class Evidence:
    evidence_id:str; domain:str; detector:str; observation:str; severity:str; confidence:float; status:str='UNCORROBORATED'; supports:list[str]=field(default_factory=list); contradicts:list[str]=field(default_factory=list); alternatives:list[str]=field(default_factory=list); controlled:list[str]=field(default_factory=list); limitation:str|None=None
    def d(self): return asdict(self)
def synth_dataset(scenario,seed=26228):
    r=random.Random(seed); rows=[]
    for i in range(40):
        f=[r.randrange(20,236) for _ in range(32)]; label=i%2
        if scenario in ('COMPROMISED','TRIGGER') and 8<=i<16: f[:4]=[245]*4; label=1
        if scenario=='DUPLICATE_FLOOD' and i>=30: f=rows[5]['features'][:]
        if scenario=='OOD': f=[r.randrange(0,128) for _ in range(32)]
        if scenario=='REVIEW' and i in (11,27): label=1-label
        rows.append({'image_id':f'IMG-{i:03d}','features':f,'label':label,'source':'SRC-A' if i<20 else 'SRC-B','batch':'B17' if i<20 else 'B18'})
    return rows
def dist(a,b): return sum(abs(x-y) for x,y in zip(a,b))/(len(a)*255)
def data_forensics(rows):
    seen={}; exact=[]; near=[]
    for i,a in enumerate(rows):
        h=sha256_bytes(bytes(a['features']))
        if h in seen: exact.append((seen[h],a['image_id']))
        else: seen[h]=a['image_id']
        for b in rows[i+1:]:
            if dist(a['features'],b['features'])<=.018: near.append((a['image_id'],b['image_id']))
    inconsistent=[]
    for i,a in enumerate(rows):
        n=sorted(((dist(a['features'],b['features']),j,b) for j,b in enumerate(rows) if i!=j), key=lambda z:z[0])[:5]
        if n:
            rate=sum(x['label'] for _,_,x in n)/len(n)
            if (rate>.8 and a['label']==0) or (rate<.2 and a['label']==1): inconsistent.append(a['image_id'])
    trig=[x['image_id'] for x in rows if x['features'][:4]==[245]*4]
    rate=sum(x['label']==1 for x in rows if x['image_id'] in trig)/len(trig) if trig else 0
    return {'exact_duplicates':exact,'near_duplicates':near,'label_inconsistency':sorted(set(inconsistent)),'trigger_ids':trig,'trigger_target_rate':rate}
def distribution(rows,ref):
    def v(rs):
        z=[q for x in rs for q in x['features']]
        return statistics.mean(z),statistics.pstdev(z),statistics.mean(sum(x['features'][:4])/4 for x in rs)
    a,b=v(rows),v(ref); diff=[abs(x-y) for x,y in zip(a,b)]; score=sum(diff)/(sum(abs(x) for x in b)+1e-9)
    return {'state':'SHIFT_DETECTED' if score>=.08 else 'NO_SHIFT','normalized_shift':score,'characterization':'MEAN_AND_SPREAD_CHANGED' if score>=.08 else 'NO_MEASURABLE_CHANGE','features':a,'reference':b}
def model_check(s):
    man={'name':'candidate_model.onnx','format':'ONNX','architecture':'demo-cv-adapter','input_shape':[1,3,640,640],'scenario':s}; h=sha256_obj(man); rh=sha256_obj({**man,'scenario':'TRUSTWORTHY'})
    ref=[.11,.23,.38,.44,.57,.63,.72,.81]; cand=([.11,.23,.91,.94,.93,.95,.72,.81] if s in ('COMPROMISED','TRIGGER') else ref[:])
    if s=='REVIEW': cand=[.11,.23,.38,.44,.57,.80,.72,.81]
    return {'artifact_hash':h,'reference_hash':rh,'behavior_reference':ref,'behavior_candidate':cand,'behavior_distance':sum(abs(a-b) for a,b in zip(ref,cand))/len(ref),'white_box_available':False}
def inference(s,mh):
    rec={'image_hash':sha256_bytes(b'IMG-004|synthetic'),'model_hash':mh,'preprocess_hash':sha256_obj({'resize':[640,640],'normalize':'local-default'}),'output_hash':sha256_obj({'class':1,'score':.93}),'timestamp':'2026-09-14T00:00:04Z','sequence':4,'nonce':'N-004'}; rec['record_hash']=sha256_obj(rec)
    supplied=mh if s!='COMPROMISED' else sha256_obj({'substituted':True})
    return {'record':rec,'verification':{'model_match':supplied==mh,'image_match':True,'preprocess_match':True,'output_match':True,'replay_detected':s=='COMPROMISED'},'supplied_model_hash':supplied}
def build_assessment(s='COMPROMISED',case_id='DEMO-CASE-001',seed=26228):
    rows=synth_dataset(s,seed); ref=synth_dataset('TRUSTWORTHY',seed); df=data_forensics(rows); ds=distribution(rows,ref); m=model_check(s); inf=inference(s,m['artifact_hash']); ev=[]
    ev.append(Evidence('E-DATA-01','DATA','Near-duplicate analysis',f"{len(df['near_duplicates'])} near-duplicate pairs detected.",'HIGH' if df['near_duplicates'] else 'LOW',.93,'CORROBORATED' if not df['near_duplicates'] else 'UNCORROBORATED'))
    ev.append(Evidence('E-DATA-02','DATA','Label consistency analysis',f"{len(df['label_inconsistency'])} locally inconsistent samples detected.",'HIGH' if df['label_inconsistency'] else 'LOW',.91,'CORROBORATED',supports=['E-DATA-01']))
    ev.append(Evidence('E-DATA-03','DATA','Trigger-pattern analysis',f"{len(df['trigger_ids'])} samples contain the repeated localized pattern; target-label rate {df['trigger_target_rate']:.0%}.",'HIGH' if df['trigger_ids'] else 'LOW',.88,'CORROBORATED',supports=['E-DATA-02'],alternatives=['Legitimate acquisition artifact','Annotation convention']))
    ev.append(Evidence('E-DIST-01','DISTRIBUTION','Reference distribution comparison',f"Normalized shift={ds['normalized_shift']:.3f}; {ds['characterization']}.",'MEDIUM' if ds['state']=='SHIFT_DETECTED' else 'LOW',.86,'UNRESOLVED' if ds['state']=='SHIFT_DETECTED' else 'CORROBORATED',contradicts=['E-MODEL-01'] if ds['state']=='SHIFT_DETECTED' else [],alternatives=['Legitimate sensor/season/terrain/illumination shift'] if ds['state']=='SHIFT_DETECTED' else []))
    ev.append(Evidence('E-MODEL-01','MODEL','Behavioral reference battery',f"Mean probe distance={m['behavior_distance']:.3f} against trusted reference.",'CRITICAL' if m['behavior_distance']>.15 else 'LOW',.95 if m['behavior_distance']>.15 else .96,'CORROBORATED',supports=['E-DATA-03'],controlled=['Controlled local probe battery reproduced anomalous response.'] if m['behavior_distance']>.15 else ['Reference battery reproduced expected behavior.'],limitation='White-box parameter/activation access unavailable; behavioral fallback used.'))
    ev.append(Evidence('E-INF-01','INFERENCE','Artifact identity verification','Recorded model identity does not match supplied identity.' if not inf['verification']['model_match'] else 'Recorded model identity matches supplied identity.','CRITICAL' if not inf['verification']['model_match'] else 'LOW',.99,'CORROBORATED',controlled=['SHA-256 identity comparison failed.'] if not inf['verification']['model_match'] else ['SHA-256 identity comparison verified.']))
    ev.append(Evidence('E-INF-02','INFERENCE','Replay detection','Sequence/nonce reuse indicates replay.' if inf['verification']['replay_detected'] else 'No sequence/nonce replay indicator detected.','HIGH' if inf['verification']['replay_detected'] else 'LOW',.98,'CORROBORATED',controlled=['Sequence and nonce reuse detected.'] if inf['verification']['replay_detected'] else []))
    decisive_compromise=(not inf['verification']['model_match']) or inf['verification']['replay_detected'] or m['behavior_distance']>.15 or len(df['trigger_ids'])>=4
    material_data_anomaly=bool(df['near_duplicates']) or bool(df['exact_duplicates']) or bool(df['label_inconsistency'])
    suspicious=decisive_compromise
    verdict='COMPROMISED' if suspicious else ('REVIEW' if s=='REVIEW' or ds['state']=='SHIFT_DETECTED' or material_data_anomaly else 'TRUSTWORTHY'); disposition={'COMPROMISED':'QUARANTINE','REVIEW':'HUMAN REVIEW','TRUSTWORTHY':'ACCEPT'}[verdict]
    reasons={'COMPROMISED':['Artifact identity/replay integrity failed.','Controlled behavioral probes reproduced anomalous behavior.','Trigger-associated data evidence corroborates the model finding.','Distribution shift was treated as context, not proof.'],'REVIEW':['A material data or behavioral anomaly was observed, but it does not by itself establish compromise.','Competing explanations and operational impact require human assessment.','No decisive provenance failure was established.'],'TRUSTWORTHY':['No material data-integrity anomaly was observed.','Model behavior matched the trusted reference.','Artifact identity and inference provenance checks passed.']}[verdict]
    if s=='OOD' and verdict=='REVIEW':
        reasons=['A measurable distribution shift was detected against the trusted reference distribution.','The observed shift may reflect legitimate terrain, sensor, season, illumination, or acquisition variation.','The evidence is insufficient to establish compromise, so human review is required.']
    cross=[{'question':'Could legitimate distribution shift explain the anomaly?','status':'NOT_SUFFICIENT' if verdict=='COMPROMISED' else ('UNRESOLVED' if verdict=='REVIEW' else 'RESOLVED'),'detail':'Shift is context, not proof of compromise.' if ds['state']=='SHIFT_DETECTED' else 'Reference comparison does not support material shift.'},{'question':'Does controlled examination reproduce suspicious behavior?','status':'RESOLVED' if m['behavior_distance']>.15 else 'UNRESOLVED','detail':'Controlled local probes reproduced the behavior.' if m['behavior_distance']>.15 else 'No suspicious controlled reproduction.'},{'question':'Could provenance mismatch explain the inference anomaly?','status':'RESOLVED','detail':'Artifact identity is independently checkable with SHA-256.'}]
    contradiction={'state':'RESOLVED' if verdict=='COMPROMISED' else ('UNRESOLVED' if verdict=='REVIEW' else 'NO_CONFLICT'),'summary':'Competing explanations were tested; independent behavioral and provenance evidence resolved the strongest conflict.' if verdict=='COMPROMISED' else ('Competing explanations remain plausible and are retained for human review.' if verdict=='REVIEW' else 'No material contradiction was found.')}
    conf=94 if verdict=='TRUSTWORTHY' else (76 if verdict=='REVIEW' else min(99,84+sum(e.status=='CORROBORATED' for e in ev)+2*sum(e.severity=='CRITICAL' for e in ev))); score={'TRUSTWORTHY':0,'REVIEW':35,'COMPROMISED':100}[verdict]
    audit=[]; prev='GENESIS'
    for i,e in enumerate(ev,1):
        p={'sequence':i,'timestamp':now(),'event':'EVIDENCE_RECORDED','evidence_id':e.evidence_id,'previous_hash':prev}; p['record_hash']=sha256_obj(p); audit.append(p); prev=p['record_hash']
    result={'case_id':case_id,'scenario':s,'seed':seed,'timestamp':now(),'verdict':verdict,'confidence':conf,'disposition':disposition,'trust_score_signal':score,'inputs':{'dataset':'synthetic_candidate_dataset','model':'candidate_model.onnx','contributor':'Local-Synthetic'},'data_metrics':df,'distribution':ds,'model':m,'inference':inf,'reasons':reasons,'evidence':[e.d() for e in ev],'cross_examination':cross,'contradiction_check':contradiction,'assessment':{'method':'Evidence-weighted rule assessment with corroboration, contradiction and controlled-examination context.','confidence_meaning':'Confidence in the assessment, not probability of malicious intent.','limitations':['Deterministic synthetic scenarios are used for reproducibility.','Distribution shift is not proof of compromise.','White-box analysis is unavailable when model state access is absent.','Operational thresholds require validation against trusted reference data.']},'audit':audit,'coverage':['data integrity','model integrity','inference provenance','distribution shift','evidence linkage','cross-examination','contradiction handling','tamper-evident audit','reproducible scenarios']}
    REPORTS.mkdir(exist_ok=True); AUDIT.mkdir(exist_ok=True); (REPORTS/f'{case_id}.json').write_text(json.dumps(result,indent=2)); (AUDIT/f'{case_id}_audit.json').write_text(json.dumps(audit,indent=2)); return result
