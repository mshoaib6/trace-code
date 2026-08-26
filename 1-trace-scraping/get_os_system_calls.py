import pickle
import re

with open("python-files-2.pkl", "rb") as f:
    files = pickle.load(f)

with open("calls.txt", "w") as f:
    pass

results = {}

def handle_match(match):
    match = match.replace('"', '').replace("'", '')
    parts = match.split()
    if len(parts) != 0:
        match = parts[0]
        results[match] = results.get(match, 0) + 1

pattern1 = r'subprocess\.run\([\'"](.*?)[\'"]\)'
pattern2 = r'os.system\([\'"](.*?)[\'"]\)'
for file in files:
    with open(file[0], 'r') as data_file:
        try:
            data = data_file.read()
            matches1 = re.findall(pattern1, data)
            matches2 = re.findall(pattern2, data)
            if matches1:
                for match in matches1:
                    handle_match(match)
            if matches2:
                for match in matches2:
                    handle_match(match)
        except UnicodeDecodeError:
            print("Unicode Decode Error")
    
with open("calls.txt", "a") as logfile:
    results = list(results.items())
    results.sort(key = lambda x: x[1], reverse = True)
    for command, count in results:
        logfile.write(command + " " + str(count) + "\n")