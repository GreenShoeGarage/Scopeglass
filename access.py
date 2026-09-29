"""Single-administrator access control. No third-party runtime dependencies."""
import hashlib
import hmac
from http.cookies import SimpleCookie, CookieError
import re
import secrets
import threading
import time

ROUNDS=600000
SESSION_SECONDS=12*60*60
MAX_SESSIONS=20
DUMMY_SALT=secrets.token_hex(16)
DUMMY_HASH=hashlib.pbkdf2_hmac('sha256',b'not-a-user-password',bytes.fromhex(DUMMY_SALT),ROUNDS).hex()


class AccessError(ValueError):
    def __init__(self,message,status=401,retry=0):
        super().__init__(message);self.status=status;self.retry=retry


def init_schema(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS auth_account(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT NOT NULL,password_hash TEXT NOT NULL,updated REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS auth_sessions(token_hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL);
    ''')


def enabled(config):return config.get('auth',{}).get('enabled',False)
def secure(config):return config.get('public_origin','').startswith('https://')
def cookie_name(config):return '__Host-scopeglass' if secure(config) else 'scopeglass'
def account(c):return c.execute('SELECT username,password_hash,updated FROM auth_account WHERE id=1').fetchone()


def password_hash(password):
    if not isinstance(password,str) or not 15<=len(password)<=128 or len(password.encode('utf-8'))>512 or '\x00' in password:
        raise ValueError('Use a passphrase of 15–128 characters (up to 512 UTF-8 bytes), without null characters.')
    salt=secrets.token_bytes(16)
    value=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,ROUNDS)
    return f'pbkdf2_sha256${ROUNDS}${salt.hex()}${value.hex()}'


def password_matches(password,encoded):
    if not isinstance(password,str) or len(password)>128 or len(password.encode('utf-8'))>512:return False
    try:
        algorithm,rounds,salt,expected=encoded.split('$')
        if algorithm!='pbkdf2_sha256' or not 600000<=int(rounds)<=2000000:return False
        actual=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),bytes.fromhex(salt),int(rounds)).hex()
        return hmac.compare_digest(actual,expected)
    except (ValueError,TypeError):return False


def set_password(c,username,password):
    if not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}',username):raise ValueError('Username: 3–64 letters, digits, dots, underscores, or hyphens.')
    encoded=password_hash(password)
    c.execute('INSERT INTO auth_account VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET username=excluded.username,password_hash=excluded.password_hash,updated=excluded.updated',(username,encoded,time.time()))
    c.execute('DELETE FROM auth_sessions')


class LoginLimiter:
    """Bounded, process-local throttling; forwarded client headers are not trusted."""
    def __init__(self):self.attempts={};self.lock=threading.Lock()
    def check(self,peer):
        now=time.monotonic()
        with self.lock:
            self.attempts={k:[x for x in v if x>now-60] for k,v in self.attempts.items() if v and v[-1]>now-60}
            recent=self.attempts.get(peer,[]);total=sum(len(v) for v in self.attempts.values())
            if len(recent)>=5 or total>=30:
                first=recent[0] if len(recent)>=5 else min(x[0] for x in self.attempts.values())
                raise AccessError('Too many sign-in attempts. Wait a minute, then try again.',429,max(1,int(61-(now-first))))
            self.attempts.setdefault(peer,[]).append(now)
    def clear(self):
        with self.lock:self.attempts.clear()


LIMITER=LoginLimiter()


def session(c,cookie,config):
    try:
        jar=SimpleCookie();jar.load(cookie or '');entry=jar.get(cookie_name(config))
        token=entry.value if entry else ''
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}',token):return None
    except CookieError:return None
    hashed=hashlib.sha256(token.encode()).hexdigest()
    row=c.execute('SELECT token_hash,csrf,expires FROM auth_sessions WHERE token_hash=? AND expires>?',(hashed,time.time())).fetchone()
    return dict(row) if row else None


def issue_session(c):
    now=time.time();c.execute('DELETE FROM auth_sessions WHERE expires<=?',(now,))
    c.execute('DELETE FROM auth_sessions WHERE token_hash IN (SELECT token_hash FROM auth_sessions ORDER BY created DESC LIMIT -1 OFFSET ?)',(MAX_SESSIONS-1,))
    token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
    c.execute('INSERT INTO auth_sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),csrf,now,now+SESSION_SECONDS))
    return token,csrf,now+SESSION_SECONDS


def cookie_header(token,config,clear=False):
    return f'{cookie_name(config)}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={0 if clear else SESSION_SECONDS}'+('; Secure' if secure(config) else '')


def login(c,username,password,old_session=None):
    user=account(c)
    encoded=user['password_hash'] if user else f'pbkdf2_sha256${ROUNDS}${DUMMY_SALT}${DUMMY_HASH}'
    valid=password_matches(password,encoded)
    if not user or not isinstance(username,str) or not hmac.compare_digest(username.encode(),user['username'].encode()) or not valid:
        raise AccessError('Username or passphrase is incorrect.')
    if old_session:c.execute('DELETE FROM auth_sessions WHERE token_hash=?',(old_session['token_hash'],))
    token,csrf,expires=issue_session(c)
    return {'enabled':True,'authenticated':True,'username':user['username'],'csrf':csrf,'expires':expires},token
