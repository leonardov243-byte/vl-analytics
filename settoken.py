
import subprocess

token = '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'

url = f'https://leonardov243-byte:{token}@github.com/leonardov243-byte/vl-analytics.git'

subprocess.run(['git', 'remote', 'set-url', 'origin', url])

print('Listo')

