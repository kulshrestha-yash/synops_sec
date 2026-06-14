import pickle
import random
import os
from pathlib import Path

random.seed(42)

NORMAL_SYSCALLS = ['open', 'read', 'write', 'close', 'socket', 'bind', 'listen', 
                   'accept', 'recv', 'send', 'fork', 'execve', 'wait', 'exit']

RANSOMWARE_PATTERN = ['open', 'read', 'encrypt', 'write', 'unlink']
REVERSE_SHELL_PATTERN = ['socket', 'connect', 'send', 'recv', 'execve']
CODE_INJECTION_PATTERN = ['mmap', 'write', 'mprotect', 'jump']

def generate_normal_sequence(length=50):
    return [random.choice(NORMAL_SYSCALLS) for _ in range(length)]

def generate_malware_sequence(length=50):
    patterns = [RANSOMWARE_PATTERN, REVERSE_SHELL_PATTERN, CODE_INJECTION_PATTERN]
    pattern = random.choice(patterns)
    
    sequence = []
    for _ in range(length):
        if random.random() < 0.7:
            sequence.append(random.choice(pattern))
        else:
            sequence.append(random.choice(NORMAL_SYSCALLS))
    
    return sequence

Path('data').mkdir(exist_ok=True)

normal_data = [generate_normal_sequence() for _ in range(500)]
malware_data = [generate_malware_sequence() for _ in range(100)]

with open('data/normal_sequences.pkl', 'wb') as f:
    pickle.dump(normal_data, f)

with open('data/malware_sequences.pkl', 'wb') as f:
    pickle.dump(malware_data, f)

print(f"Generated {len(normal_data)} normal sequences")
print(f"Generated {len(malware_data)} malware sequences")
print("Saved to data/ directory")
