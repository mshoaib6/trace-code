import subprocess
import pickle
import os
import glob
import shutil
import ast
import autopep8
from lib2to3 import refactor
import lib2to3
import sys

with open('docker_template.txt', 'r') as f:
    docker_template = f.read()

with open('foldernames.pkl', 'rb') as f:
    foldernames = pickle.load(f)

with open('total_results.pkl', 'rb') as f:
    total_results = pickle.load(f)

success = 0
failed = 0
bad_return_code = 0
bad_parse = 0
multiple_files = 0
timeout = 0

def run_strace_on_folder(foldername, filename):
    global success, failed, bad_return_code, timeout
    modified_template = docker_template.replace("[DIRNAME]", 'tmp').replace("[PYTHONFILENAME]", filename)
    with open('Dockerfile', 'w') as f:
        f.write(modified_template)
    subprocess.run(['docker', 'build', '-t', 'python-docker', '.'])
    try:
        print(foldername, '/', filename)
        # output = subprocess.run(['docker', 'run', '--rm', 'python-docker:latest'], check=True, capture_output=True)
        child = subprocess.Popen(['docker', 'run', '--rm', 'python-docker:latest'], stdout=sys.stdout, stderr=sys.stderr)
        try:
            outs, errs = child.communicate(timeout=120)
            output = child
            if output.returncode == 0:
                print(output.stdout)
                success += 1
                return
            else:
                print('status code', output.returncode)
                bad_return_code += 1
                with open('return_codes.txt', 'a') as f:
                    f.write(f'{foldername}/{filename}, {output.returncode}, stdout: {output.stdout}, stderr: {output.stderr}\n')
                return
        except subprocess.TimeoutExpired:
            child.kill()
            outs, errs = child.communicate()
            timeout += 1
    except subprocess.CalledProcessError as e:
        print(e.output)
        print("failed")
        print('foldername ', foldername)
        print('filename ', filename)
        failed += 1

for folder in foldernames:
    data = total_results[total_results['Foldername'] == folder].iloc[0]
    CVE = data['CVE ID']
    lowercase_cve = CVE.replace('CVE', 'cve')
    full_folder = os.path.join('total-folder/', folder)
    if 'edb' in folder:
        filename = CVE + '.py'
    else:
        if os.path.isfile(os.path.join(full_folder, CVE + '.py')):
            filename = CVE + '.py'
        elif os.path.isfile(os.path.join(full_folder, lowercase_cve + '.py')):
            filename = lowercase_cve + '.py'
        elif os.path.isfile(os.path.join('full_folder', 'main.py')):
            filename = 'main.py'
        else:
            files = glob.glob(os.path.join(full_folder, '*.py'), recursive=False)
            if len(files) == 1:
                filename = files[0].split('/')[-1]
            else:
                print("multiple python files, cannot choose: ", full_folder)
                multiple_files += 1
                continue
    shutil.rmtree('tmp')
    shutil.copytree(full_folder, 'tmp')
    with open(os.path.join(full_folder, filename), 'r') as f:
        try:
            file_data = f.read()
            try:
                try:
                    tree = ast.parse(file_data)
                except SyntaxError:
                        print('python2 error')
                        autopep8.fix_code(file_data)
                        fixer_names = refactor.get_fixers_from_package('lib2to3.fixes')
                        fixer = refactor.RefactoringTool(fixer_names)
                        file_data = str(fixer.refactor_string(file_data, filename))
                        tree = ast.parse(file_data)
                        with open(os.path.join('tmp', filename), 'w') as f:
                            f.write(file_data)
            except TabError:
                try:
                    print('python2 error')
                    normalized_code = autopep8.fix_code(data)
                    tree = ast.parse(normalized_code)
                    with open(os.path.join('tmp', filename), 'w') as f:
                        f.write(file_data)
                except:
                    print('python parsing error')
                    bad_parse += 1
                    continue
            except (lib2to3.pgen2.parse.ParseError, lib2to3.pgen2.tokenize.TokenError, IndentationError, SyntaxError) as error:
                print('python parsing error')
                bad_parse += 1
                continue
            run_strace_on_folder(full_folder, filename)
        except UnicodeDecodeError:
            print('python parsing error')
            bad_parse += 1
            continue

print("Succeeded: ", success)
print("Exception Failed: ", failed)
print("Status code fails: ", bad_return_code)
print("Parse fail: ", bad_parse)
print("Too many files fail: ", multiple_files)
print("Timeout: ", timeout)
print("Total: ", success + failed + bad_return_code + bad_parse + multiple_files + timeout)