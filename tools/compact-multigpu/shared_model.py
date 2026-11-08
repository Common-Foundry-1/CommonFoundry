"""Private, owner-checked Unix RPC for replay in the fixed GPU process."""
import contextlib,json,os,socket,stat,struct,threading,time,fcntl
from pathlib import Path
MAX_LINE=65536
def receive(connection):
    data=bytearray()
    while not data.endswith(b'\n'):
        part=connection.recv(1)
        if not part or len(data)>=MAX_LINE:raise ValueError('bounded shared-model request')
        data+=part
    return json.loads(data)
def peer(connection):
    pid,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if uid!=os.geteuid():raise PermissionError('shared model peer has another owner')
def private_parent(path):
    if not path.is_absolute() or '..' in path.parts or len(os.fsencode(path))>103:raise ValueError('shared model needs a short absolute socket path')
    info=path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise PermissionError('shared model directory must be owned and mode 0700')
def request(path,value):
    path=Path(path);private_parent(path);info=path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise PermissionError('invalid shared-model socket')
    encoded=json.dumps(value,separators=(',',':')).encode()+b'\n'
    if len(encoded)>MAX_LINE:raise ValueError('oversized replay request')
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(600);connection.connect(str(path));peer(connection);connection.sendall(encoded);result=receive(connection)
    if result.get('ok') is not True:raise RuntimeError(result.get('error','shared replay failed'))
    return result
class Server:
    def __init__(self,path,session,model):
        self.path=Path(path);private_parent(self.path)
        lease=Path(str(self.path)+'.lock')
        self.lease=os.open(lease,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            info=os.fstat(self.lease)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise PermissionError('invalid shared-model lease')
            fcntl.flock(self.lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if self.path.exists() or self.path.is_symlink():
                info=self.path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise PermissionError('invalid existing shared-model endpoint')
                with socket.socket(socket.AF_UNIX) as check:
                    check.settimeout(.2)
                    try:check.connect(str(self.path))
                    except ConnectionRefusedError:pass
                    else:raise FileExistsError('shared-model service is already active')
                if self.path.lstat().st_ino!=info.st_ino:raise RuntimeError('shared-model endpoint changed during recovery')
                self.path.unlink()
        except BaseException:os.close(self.lease);raise
        self.session=session;self.model=str(Path(model).resolve(strict=True));self.stop=threading.Event()
        self.listener=socket.socket(socket.AF_UNIX);self.listener.bind(str(self.path));os.chmod(self.path,0o600);self.socket_inode=self.path.stat().st_ino;self.listener.listen(8);self.listener.settimeout(.2)
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stop.is_set():
            try:connection,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:return
            with connection:
                try:
                    connection.settimeout(30);peer(connection);value=receive(connection)
                    if value.get('op')=='ping':
                        if str(Path(value['model']).resolve(strict=True))!=self.model:raise ValueError('replay model differs from the resident model')
                        result={'ok':True,'resident':True}
                    else:result=self.session.replay(value)
                    connection.sendall(json.dumps(result,separators=(',',':')).encode()+b'\n')
                except BaseException as error:
                    with contextlib.suppress(OSError):connection.sendall(json.dumps({'ok':False,'error':str(error)}).encode()+b'\n')
    def close(self):
        self.stop.set();self.listener.close();self.thread.join(timeout=605)
        if self.thread.is_alive():raise RuntimeError('resident replay did not stop')
        if self.path.exists() and self.path.lstat().st_ino==self.socket_inode:self.path.unlink()
        os.close(self.lease)
