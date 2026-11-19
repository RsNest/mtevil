#!/usr/bin/env python3
"""Restore only the temporary mtveil HAProxy route; preserve unrelated edits."""
import argparse,fcntl,hashlib,json,os,shutil,signal,subprocess,tempfile,threading,time
from pathlib import Path

def sha(data):return hashlib.sha256(data).hexdigest()
def run(args):return subprocess.run(args,capture_output=True,text=True,timeout=20,check=True).stdout
def restore(state_path):
    state=json.loads(state_path.read_text());root=state_path.parent
    with (root/'restore.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        config=Path(state['config']);current=config.read_bytes()
        if sha(current)==state['original_sha256']:
            outcome='already_original'
        else:
            if sha(current)==state['patched_sha256']:
                restored=Path(state['backup']).read_bytes()
            else:
                text=current.decode()
                for block in [state['route'],state['backend']]:
                    if text.count(block)!=1:raise RuntimeError('route restoration conflict: manual review required')
                    text=text.replace(block,'',1)
                restored=text.encode()
            fd,name=tempfile.mkstemp(prefix='.mtveil-restore-',dir=config.parent);os.close(fd)
            temp=Path(name)
            try:
                shutil.copy2(config,temp);temp.write_bytes(restored)
                run(['/usr/sbin/haproxy','-c','-f',str(temp)])
                os.replace(temp,config)
                run(['systemctl','reload','haproxy.service'])
            finally:
                if temp.exists():temp.unlink()
            outcome='restored'
        subprocess.run(['systemctl','stop',state['unit']],capture_output=True,text=True,timeout=20,check=False)
        active=run(['systemctl','show',state['unit'],'-p','ActiveState','--value']).strip()
        if active in ['active','activating','deactivating']:raise RuntimeError('test service did not stop')
        result={'event':'443_restored','outcome':outcome,'unix':int(time.time()),'config_sha256':sha(config.read_bytes())}
        (root/'restoration.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--state',type=Path,required=True);parser.add_argument('--restore',action='store_true');args=parser.parse_args()
    if args.restore:restore(args.state);return
    state=json.loads(args.state.read_text());stop=threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stop.set());signal.signal(signal.SIGINT,lambda *_:stop.set())
    try:
        while time.time()<state['expires_unix'] and not stop.is_set():
            active=run(['systemctl','show',state['unit'],'-p','ActiveState','--value']).strip()
            if active not in ['active','activating']:break
            stop.wait(5)
    finally:restore(args.state)

if __name__=='__main__':main()
