import os

with open('scripts/e2e_scenario.py', 'r') as f:
    text = f.read()
text = text.replace('election_id = 8', 'election_id = 9')
text = text.replace('"election_id": 8', '"election_id": 9')
text = text.replace('"election_id":8', '"election_id":9')
text = text.replace('engine.run(8)', 'engine.run(9)')
text = text.replace('backup.write(8', 'backup.write(9')
text = text.replace('recovery.recover(8', 'recovery.recover(9')
text = text.replace('Election 8', 'Election 9')
with open('scripts/e2e_scenario.py', 'w') as f:
    f.write(text)

with open('scripts/create_election.py', 'r') as f:
    text = f.read()
text = text.replace('"election_id": 8', '"election_id": 9')
text = text.replace('Election 8', 'Election 9')
with open('scripts/create_election.py', 'w') as f:
    f.write(text)
    
with open('scripts/true_tampering.py', 'r') as f:
    text = f.read()
text = text.replace(', 8', ', 9')
text = text.replace('(8)', '(9)')
text = text.replace(': 8', ': 9')
text = text.replace('Election 8', 'Election 9')
with open('scripts/true_tampering.py', 'w') as f:
    f.write(text)
