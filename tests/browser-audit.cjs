// Focused audit of empty states, live pagination, stale queries, and responsive themes.
const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),cp=require('child_process'),assert=require('assert');
const root=path.resolve(__dirname,'..'),tmp=fs.mkdtempSync(path.join(os.tmpdir(),'scopeglass-audit-'));
const database=path.join(tmp,'audit.db'),config=path.join(tmp,'config.json'),base='http://127.0.0.1:18766';
fs.writeFileSync(config,JSON.stringify({listen_host:'127.0.0.1',listen_port:18766,allowed_cidrs:['127.0.0.0/8'],database}));
const delay=ms=>new Promise(r=>setTimeout(r,ms));let server,browser;const errors=[];
function seed(count){return cp.execFileSync('python3',['-c',`import sqlite3,json,datetime,sys
c=sqlite3.connect(sys.argv[1]);n=int(sys.argv[2]);now=datetime.datetime.now(datetime.timezone.utc).isoformat();hosts=['127.0.0.'+str(i) for i in range(1,n+1)]
sid=c.execute("INSERT INTO scans(started,finished,status,targets,ports,total,checked) VALUES(?,?,'complete',?,?,?,?)",(now,now,json.dumps(hosts),'[2323]',n,n)).lastrowid
for host in hosts:
 c.execute('INSERT INTO observations(scan_id,host,port,service,banner,observed,metadata) VALUES(?,?,?,?,?,?,?)',(sid,host,2323,'telnet','login: workshop fixture',now,json.dumps({'protocol':'telnet','identification':'verified','evidence':['Telnet option negotiation observed.']})))
 c.execute('INSERT INTO checks VALUES(?,?,?,?)',(sid,host,2323,'open'))
c.commit();print(sid)`,database,String(count)],{encoding:'utf8'}).trim()}
(async()=>{try{
 server=cp.spawn('python3',[path.join(root,'server.py'),'--config',config],{stdio:'ignore'});
 for(let n=0;n<60;n++){try{if((await fetch(base+'/api/status')).ok)break}catch{}await delay(100)}
 browser=await chromium.launch({headless:true,args:['--no-sandbox'],...(process.env.SCOPEGLASS_BROWSER?{executablePath:process.env.SCOPEGLASS_BROWSER}:{})});
 const page=await browser.newPage({viewport:{width:1440,height:1100}});page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.locator('#empty-start').waitFor();assert(await page.locator('#scan-button').isDisabled());await page.screenshot({path:path.join(root,'docs','empty.png'),fullPage:true});await page.click('#empty-start');assert(await page.evaluate(()=>document.activeElement.id==='network'));
 const first=seed(26);await page.click('#refresh');await page.waitForFunction(()=>document.getElementById('host-count').textContent==='26');await page.click('#next');await page.waitForFunction(()=>document.getElementById('page-label').textContent.startsWith('21–26'));
 const second=seed(1);await page.waitForFunction(()=>document.getElementById('page-label').textContent.startsWith('1–1')&&document.getElementById('host-count').textContent==='1',{},{timeout:12000});assert((await page.textContent('#coverage')).includes('Scan #'+second));
 // An in-flight response must not render under a newer search string.
 let released=false;await page.route('**/api/observations?*',async route=>{const url=new URL(route.request().url());if(url.searchParams.get('q')==='port:22'){await delay(550);released=true}await route.continue()});
 await page.fill('#query','port:22');await delay(230);await page.fill('#query','port:2323');await page.waitForFunction(()=>document.getElementById('port-count').textContent==='1');await delay(650);assert(released);assert(await page.textContent('#port-count')==='1');assert(await page.inputValue('#query')==='port:2323');await page.unroute('**/api/observations?*');await page.click('#clear-filters');
 // Core text/field/action contrast, calculated from rendered theme colors.
 function contrast([a,b]){const rgb=c=>(c.match(/[\d.]+/g)||[]).slice(0,3).map(Number).map(x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4});const lum=c=>rgb(c).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);const x=lum(a),y=lum(b);return (Math.max(x,y)+.05)/(Math.min(x,y)+.05)}
 for(const theme of ['dark','light','contrast']){await page.selectOption('#theme',theme);const pairs=await page.evaluate(()=>{const body=getComputedStyle(document.body),field=getComputedStyle(document.getElementById('query')),primary=getComputedStyle(document.getElementById('easy-mode')),note=getComputedStyle(document.querySelector('.note')),panel=getComputedStyle(document.querySelector('.panel'));return [[body.color,body.backgroundColor],[field.color,field.backgroundColor],[primary.color,primary.backgroundColor],[note.color,panel.backgroundColor]]});for(const pair of pairs)assert(contrast(pair)>=4.5,theme+': contrast '+contrast(pair));await page.screenshot({path:path.join(root,'docs','audit-'+theme+'.png'),fullPage:true})}
 await page.selectOption('#theme','dark');
 // A cold mobile revisit brings observations into view; setup remains reachable.
 await page.setViewportSize({width:390,height:844});await page.reload();await page.waitForFunction(()=>document.getElementById('host-count').textContent==='1');assert(!(await page.locator('#assessment-setup').evaluate(el=>el.open)));await page.screenshot({path:path.join(root,'docs','audit-mobile.png'),fullPage:true});await page.locator('#assessment-setup > summary').click();assert(await page.locator('#targets').isVisible());await page.locator('#assessment-setup > summary').click();
 for(const width of [320,390,768,1280]){await page.setViewportSize({width,height:900});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth), 'overflow at '+width);await page.locator('#device-list [data-inspect]').first().click();await page.waitForFunction(()=>document.getElementById('inspector').open);assert(await page.locator('#inspector').evaluate(el=>el.scrollWidth<=el.clientWidth));await page.keyboard.press('Escape');await page.waitForFunction(()=>!document.getElementById('inspector').open);assert(await page.evaluate(()=>document.activeElement.matches('[data-inspect]')||document.activeElement.id==='results-title'))}
 assert.deepEqual(errors,[]);console.log('PASS: empty-state guidance, latest-scan pagination recovery, stale-search response protection, dark/light/contrast core text ≥4.5:1, mobile revisit and setup, 320/390/768/1280px overflow, inspector Escape/focus return, zero JS errors');
}finally{if(browser)await browser.close();if(server)server.kill()}})().catch(e=>{console.error(e);process.exitCode=1});
