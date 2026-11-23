import os
p = 'engines/dataset_config.json'
if os.path.exists(p):
    with open(p, 'r', encoding='utf-8') as f:
        text = f.read()
    with open(p, 'w', encoding='utf-8') as f:
        f.write(text.replace('192.168.x.x', 'Local Dev'))
