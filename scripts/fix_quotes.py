path = r'k:\craftathon\cyphra-android\app\src\main\java\com\cyphra\messenger\data\repository\MessengerRepository.kt'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Fix line 173 (0-indexed: 172)
old = lines[172]
# Replace the broken string with correct escaped version
lines[172] = '                return Result.failure(Exception("No Cyphra account found for that email"))\n'

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print("Fixed:", repr(lines[172].strip()))
