#!/usr/bin/env python3
"""Bounded live-test monitor. No packet capture, credentials or peer addresses."""
import argparse
import json
import os
import signal
import threading
from pathlib import Path
import subprocess
import time

def command(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=10)
    if p.returncode:raise RuntimeError('monitor command failed: '+args[0])
    return p.stdout

def services():
    names=['undead-telemt.service','undead-mtdd-test.service','nginx.service','haproxy.service']
    text=command(['systemctl','show',*names,'-p','Id','-p','ActiveState','-p','MainPID'])
    return [dict(line.split('=',1) for line in block.splitlines() if '=' in line) for block in text.strip().split('\n\n')]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--unit',required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--duration',type=int,default=7200)
    parser.add_argument('--firewall-ip',required=True)
    parser.add_argument('--firewall-port',required=True)
    parser.add_argument('--tag',required=True)
    parser.add_argument('--no-firewall-cleanup',action='store_true')
    parser.add_argument('--watch-containers',nargs='*',default=[])
    args=parser.parse_args()
    os.umask(0o077)
    args.out.mkdir(exist_ok=True)
    path=args.out/'observations.jsonl'
    def emit(event):
        if path.exists() and path.stat().st_size>=8*1024*1024:
            oldest=path.with_name(path.name+'.3')
            if oldest.exists():oldest.unlink()
            for n in [2,1]:
                source=path.with_name(path.name+f'.{n}')
                if source.exists():source.rename(path.with_name(path.name+f'.{n+1}'))
            path.rename(path.with_name(path.name+'.1'))
        event['observed_unix_ms']=int(time.time()*1000)
        with path.open('a') as f:f.write(json.dumps(event)+'\n')
    stopped=threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stopped.set())
    signal.signal(signal.SIGINT,lambda *_:stopped.set())
    baseline=services()
    def containers():
        if not args.watch_containers:return []
        return command(['docker','inspect','--format','{{.Id}} {{.State.Status}} {{.State.Pid}}',*args.watch_containers]).splitlines()
    baseline_containers=containers()
    (args.out/'production-baseline.json').write_text(json.dumps(baseline,indent=2))
    cursor=None;deadline=time.monotonic()+args.duration;bad_memory=bad_load=0
    emit({'event':'monitor_started','duration_seconds':args.duration})
    try:
        while time.monotonic()<deadline and not stopped.is_set():
            props=dict(line.split('=',1) for line in command(['systemctl','show',args.unit,'-p','ActiveState','-p','MainPID','-p','MemoryCurrent','-p','CPUUsageNSec','-p','NRestarts','-p','Result']).splitlines() if '=' in line)
            memory=dict((a,int(b.split()[0])) for a,b in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines()))
            load=float(Path('/proc/loadavg').read_text().split()[0])
            pid=props.get('MainPID','0');rss=fd=None
            if pid!='0':
                try:
                    status=Path(f'/proc/{pid}/status').read_text().splitlines()
                    rss=next(int(line.split()[1]) for line in status if line.startswith('VmRSS:'))
                    fd=len(list(Path(f'/proc/{pid}/fd').iterdir()))
                except (OSError,StopIteration):pass
            emit({'event':'sample','unit':props,'rss_kib':rss,'fd':fd,'host_mem_available_kib':memory.get('MemAvailable'),'host_load1':load})
            journal=['journalctl','-u',args.unit,'-o','json','--no-pager','-n','1000']
            if cursor:journal+=['--after-cursor',cursor]
            else:journal+=['--since','-3min']
            for line in command(journal).splitlines():
                try:entry=json.loads(line)
                except ValueError:continue
                cursor=entry.get('__CURSOR',cursor)
                message=entry.get('MESSAGE','')
                try:message=json.loads(message)
                except (ValueError,TypeError):message=str(message)[:500]
                emit({'event':'application_log','journal_ts':entry.get('__REALTIME_TIMESTAMP'),'message':message})
            bad_memory=bad_memory+1 if memory.get('MemAvailable',0)<512*1024 else 0
            bad_load=bad_load+1 if load>2.0 else 0
            current=services()
            current_containers=containers()
            if bad_memory>=2 or bad_load>=3 or current!=baseline or current_containers!=baseline_containers:
                emit({'event':'guard_stop','reason':'host_memory' if bad_memory>=2 else 'host_load' if bad_load>=3 else 'production_service_changed' if current!=baseline else 'production_container_changed'})
                break
            if props.get('ActiveState') not in ['active','activating']:
                emit({'event':'test_stopped','reason':props.get('Result')});break
            stopped.wait(15)
    except Exception as exc:
        emit({'event':'monitor_error','error':type(exc).__name__})
        raise
    finally:
        subprocess.run(['systemctl','stop',args.unit],timeout=20,check=False)
        rule=['ufw','--force','delete','allow','in','proto','tcp','to',args.firewall_ip,'port',args.firewall_port,'comment',args.tag]
        firewall_result=None
        if not args.no_firewall_cleanup:
            firewall_result=subprocess.run(rule,capture_output=True,text=True,timeout=20).returncode
        emit({'event':'test_cleanup','firewall_remove_exit':firewall_result,'production_services':services()})

if __name__=='__main__':main()
