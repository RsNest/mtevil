#!/usr/bin/env python3
"""Isolated Compose lifecycle smoke. Run on a disposable Linux development host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    project='mtveil-release-smoke'
    env=dict(os.environ,MTVEIL_BIND='127.0.0.1',MTVEIL_PORT='25443')
    compose=['docker','compose','-p',project,'-f','deploy/compose.yaml']
    rollback='mtveil:release-smoke-rollback'
    result={'status':'FAIL','scope':'isolated Compose lifecycle, no Telegram DC validation'}
    created=False
    logs=[]
    def command(argv,check=True,alternate=None):
        p=subprocess.run(argv,env=alternate or env,capture_output=True,text=True,timeout=60)
        if check and p.returncode:
            raise RuntimeError('command failed: '+ ' '.join(argv[:6])+'; '+p.stderr[:300])
        return p
    def dc(*argv,**kwargs):return command(compose+list(argv),**kwargs)
    def cid():return dc('ps','-q','mtveil').stdout.strip()
    def inspect():return json.loads(command(['docker','inspect',cid()]).stdout)[0]
    def healthy():
        limit=time.monotonic()+45
        while time.monotonic()<limit:
            ident=cid()
            if ident:
                data=inspect()
                if data['State'].get('Health',{}).get('Status')=='healthy':return data
            time.sleep(0.5)
        raise TimeoutError('container not healthy within 45s')
    def link():
        # Capture credentials locally without printing them or including them in evidence.
        return dc('exec','-T','mtveil','mtveil','link','--config','/etc/mtveil/config.json','--server','127.0.0.1','--port','25443').stdout.strip()
    try:
        if command(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project]).stdout.strip():
            raise RuntimeError('smoke project already exists; left untouched')
        if command(['docker','volume','inspect',project+'_state'],check=False).returncode==0:
            raise RuntimeError('smoke volume already exists; left untouched')
        dc('config','--quiet')
        created=True
        dc('--profile','tools','run','--rm','init')
        dc('run','--rm','--no-deps','mtveil','--config','/etc/mtveil/config.json','--check-config')
        dc('up','-d','mtveil')
        data=healthy()
        assert data['Config']['User']=='10001:10001'
        assert data['HostConfig']['ReadonlyRootfs'] is True
        assert 'ALL' in data['HostConfig']['CapDrop']
        assert data['HostConfig']['Memory']==256*1024*1024
        first=link()
        assert first.startswith('https://t.me/proxy?server=127.0.0.1&port=25443&secret=ee')
        assert dc('--profile','tools','run','--rm','init',check=False).returncode!=0
        assert link()==first
        dc('stop','mtveil')
        stopped=json.loads(command(['docker','inspect',data['Id']]).stdout)[0]
        assert stopped['State']['ExitCode']==0
        dc('up','-d','mtveil')
        data=healthy();assert link()==first
        # Kill the application, not Docker's manually-stopped flag; restart policy must recover it.
        time.sleep(10)
        before=data['RestartCount']
        command(['docker','exec',data['Id'],'/bin/sh','-c',
                 'for p in /proc/[0-9]*/comm; do read -r name < "$p" || continue; if [ "$name" = mtveil ]; then n=${p#/proc/}; n=${n%/comm}; kill -KILL "$n"; exit; fi; done'])
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            data=healthy()
            if data['RestartCount']>before:break
            time.sleep(0.5)
        assert data['RestartCount']>before and link()==first
        command(['docker','image','tag','mtveil:0.1.0-alpha.1',rollback])
        rollback_env=dict(env,MTVEIL_IMAGE=rollback)
        dc('up','-d','--no-build','mtveil',alternate=rollback_env)
        data=healthy()
        assert data['Config']['Image']==rollback and link()==first
        result.update(status='PASS',non_root=True,read_only_rootfs=True,
                      secret_preserved_after_init_refusal=True,secret_preserved_after_restart=True,
                      sigterm_exit=stopped['State']['ExitCode'],crash_restart=True,
                      rollback_reference_test=True,secret_preserved_after_rollback=True,
                      image_id=data['Image'],credential_link_sha256=hashlib.sha256(first.encode()).hexdigest())
    except Exception as exc:
        result['error']=type(exc).__name__+': '+str(exc)
        raise
    finally:
        if created:
            logs.append(dc('logs','--no-color','mtveil',check=False).stdout)
            dc('down','-v',check=False)
            command(['docker','image','rm',rollback],check=False)
        (args.out/'deployment-smoke.json').write_text(json.dumps(result,indent=2))
        (args.out/'dut.log').write_text(''.join(logs))
    print(json.dumps(result))


if __name__=='__main__':main()
