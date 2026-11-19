#!/usr/bin/env python3
"""Read-only bounded observation of test-unit logs and HAProxy counters."""
import argparse,csv,io,json,os,selectors,socket,subprocess,time
from pathlib import Path

def cli(command):
    s=socket.socket(socket.AF_UNIX);s.settimeout(2)
    try:
        s.connect('/run/haproxy/admin.sock');s.sendall(command.encode()+b'\n');s.shutdown(socket.SHUT_WR)
        data=bytearray()
        while True:
            block=s.recv(65536)
            if not block:break
            data.extend(block)
            if len(data)>2*1024*1024:raise RuntimeError('oversize statistics')
        return data.decode()
    finally:s.close()

def main():
    p=argparse.ArgumentParser();p.add_argument('--unit',required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--ready',type=Path,required=True);p.add_argument('--stop',type=Path,required=True);p.add_argument('--duration',type=int,default=300);a=p.parse_args()
    os.umask(0o077);start=time.monotonic();deadline=start+min(a.duration,300)
    def emit(event):
        event.update(observed_unix_ms=int(time.time()*1000),window_mono_ms=int((time.monotonic()-start)*1000))
        with a.out.open('a') as f:f.write(json.dumps(event)+'\n')
        if a.out.stat().st_size>2*1024*1024:raise RuntimeError('observation size limit')
    def sample():
        info=dict(line.split(': ',1) for line in cli('show info').splitlines() if ': ' in line)
        rows=csv.DictReader(io.StringIO(cli('show stat').replace('# pxname','pxname',1)))
        fields=['pxname','svname','scur','stot','bin','bout','qcur','econ','eresp','cli_abrt','srv_abrt','wretr','wredis','status']
        selected=[{k:row.get(k) for k in fields} for row in rows if row.get('pxname') in ['se_443','mtevil_live_test']]
        proc=Path('/sys/fs/cgroup/system.slice')/a.unit/'cgroup.procs'
        emit({'event':'sample','haproxy_worker_pid':info.get('Pid'),'haproxy_uptime_sec':info.get('Uptime_sec'),'dut_pids':proc.read_text().split() if proc.exists() else [],'counters':selected})
    journal=subprocess.Popen(['journalctl','-u',a.unit,'-f','-n','0','-o','json','--no-pager'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    os.set_blocking(journal.stdout.fileno(),False)
    selector=selectors.DefaultSelector();selector.register(journal.stdout,selectors.EVENT_READ)
    try:
        emit({'event':'window_started','unit':a.unit,'duration_seconds':min(a.duration,300)})
        sample()
        a.ready.write_text(json.dumps({'ready':True,'started_unix_ms':int(time.time()*1000),'duration_seconds':min(a.duration,300)}))
        next_sample=time.monotonic()+1
        buffered=bytearray();stop_due=None
        while time.monotonic()<deadline:
            if a.stop.exists() and stop_due is None:stop_due=time.monotonic()+8
            if stop_due is not None and time.monotonic()>=stop_due:break
            for key,_ in selector.select(timeout=min(.2,max(0,next_sample-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk:raise RuntimeError('journal follower stopped')
                buffered.extend(chunk)
                while b'\n' in buffered:
                    line,_,remainder=buffered.partition(b'\n');buffered=bytearray(remainder)
                    try:entry=json.loads(line)
                    except ValueError:continue
                    message=entry.get('MESSAGE','')
                    try:message=json.loads(message)
                    except (ValueError,TypeError):message=str(message)[:500]
                    emit({'event':'application_log','journal_cursor':entry.get('__CURSOR'),'journal_unix_us':entry.get('__REALTIME_TIMESTAMP'),'message':message})
            if time.monotonic()>=next_sample:
                sample();next_sample=time.monotonic()+1
        sample();emit({'event':'window_finished','reason':'user_stop' if a.stop.exists() else 'duration_limit'})
    except Exception as e:
        emit({'event':'capture_error','error':type(e).__name__});raise
    finally:
        selector.close();journal.terminate()
        try:journal.wait(timeout=3)
        except subprocess.TimeoutExpired:journal.kill();journal.wait(timeout=3)

if __name__=='__main__':main()
