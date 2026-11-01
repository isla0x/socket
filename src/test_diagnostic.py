from pathlib import Path
from backend import agent_source
root=Path(__file__).resolve().parent
config=dict(profile='shinyoung',diagnostic='attach',compatibility=True)
source=agent_source(config,root/'does-not-exist.js')
assert 'Java' not in source and '.implementation' not in source and '10000' in source
config['diagnostic']='java'
source=agent_source(config,root/'does-not-exist.js')
assert 'Java.perform' in source and 'Java.use' not in source and '.implementation' not in source
config['diagnostic']='capture'
source=agent_source(config,root/'agent-shinyoung.js')
assert 'SocketManager' in source and 'RootedCheck' not in source
source=agent_source(dict(profile='kyobo',diagnostic='attach',compatibility=False),root/'agent.js')
assert 'makePacketArray' in source
print('PASS: attach-only excludes Java/hooks/prelude, Java-only excludes hooks, capture and Kyobo unchanged.')
