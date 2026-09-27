import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from src.core import build_assessment

expected = {
    'COMPROMISED': ('COMPROMISED','QUARANTINE'),
    'REVIEW': ('REVIEW','HUMAN REVIEW'),
    'TRUSTWORTHY': ('TRUSTWORTHY','ACCEPT'),
    'DUPLICATE_FLOOD': ('REVIEW','HUMAN REVIEW'),
    'OOD': ('REVIEW','HUMAN REVIEW'),
    'TRIGGER': ('COMPROMISED','QUARANTINE'),
}
for s,(v,d) in expected.items():
    r=build_assessment(s,'TEST-'+s)
    assert (r['verdict'],r['disposition'])==(v,d),(s,r['verdict'],r['disposition'])
    assert len(r['evidence'])==7
    assert len(r['audit'])==7
print('ALL CORE TESTS PASSED')
