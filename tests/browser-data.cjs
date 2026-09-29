// Recovery and output workflows against a real server; synthetic loopback history only.
const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),cp=require('child_process'),assert=require('assert');
const root=path.resolve(__dirname,'..'),tmp=fs.mkdtempSync(path.join(os.tmpdir(),'scopeglass-data-'));
const database=path.join(tmp,'data.db'),config=path.join(tmp,'config.json'),base='http://127.0.0.1:18767';
fs.writeFileSync(config,JSON.stringify({listen_host:'127.0.0.1',listen_port:18767,allowed_cidrs:['127.0.0.0/8'],database}));
const delay=ms=>new Promise(r=>setTimeout(r,ms));let server,browser;const errors=[];
async function api(route,body){const status=await fetch(base+'/api/status'),headers={'Content-Type':'application/json','X-Scopeglass-Epoch':status.headers.get('x-scopeglass-epoch')};const response=await fetch(base+'/api/'+route,body===undefined?{}:{method:'POST',headers,body:JSON.stringify(body)});const value=await response.json();assert(response.ok,JSON.stringify(value));return value}
function seed(){cp.execFileSync('python3',['-c',`import sqlite3,json,datetime,sys
c=sqlite3.connect(sys.argv[1]);now=datetime.datetime.now(datetime.timezone.utc).isoformat()
for started in ('2001-01-01T00:00:00+00:00',now):
 sid=c.execute("INSERT INTO scans(started,finished,status,targets,ports,total,checked) VALUES(?,?,'complete',?,?,4,4)",(started,started,'["127.0.0.1","127.0.0.2"]','[2323,8080]')).lastrowid
 for host in ('127.0.0.1','127.0.0.2'):
  for port in (2323,8080):
   metadata={'protocol':'telnet','identification':'verified'} if port==2323 else {'protocol':'http','identification':'verified','http':{'title':'Workshop Camera <img src=x>','status':200,'server':'Fixture'},'device':{'kind':'camera','label':'Likely camera / video device','confidence':'medium','evidence':'Advertised camera title; identity unverified.'}}
   c.execute('INSERT INTO observations(scan_id,host,port,service,banner,observed,metadata) VALUES(?,?,?,?,?,?,?)',(sid,host,port,'fixture','Response, "quoted"\\nnext line',started,json.dumps(metadata)))
   c.execute('INSERT INTO checks VALUES(?,?,?,?)',(sid,host,port,'open'))
c.commit()`,database])}
async function manage(page){await page.locator('#assessment-setup').evaluate(el=>el.open=true);await page.locator('summary').filter({hasText:'Save and recover'}).evaluate(el=>el.parentElement.open=true);await page.click('#manage-data');await page.waitForFunction(()=>document.getElementById('data-dialog').open)}
async function preview(page,action){await page.selectOption('#data-action',action);await page.click('#data-preview');await page.locator('#data-confirm-fields').waitFor({state:'visible'});assert(await page.locator('#data-apply').isDisabled());assert(await page.evaluate(()=>document.activeElement.id==='data-confirm'))}
(async()=>{try{
 server=cp.spawn('python3',[path.join(root,'server.py'),'--config',config],{stdio:'ignore'});
 for(let n=0;n<60;n++){try{if((await fetch(base+'/api/status')).ok)break}catch{}await delay(100)}seed();
 const asset=(await api('device?host=127.0.0.1&scan=2')).asset;
 await api('device',{...asset,name:'=HYPERLINK("fixture")',tags:['workshop'],notes:'+SUM(1,2)\nOwner: "test"',expected_ports:[2323]});
 await api('schedules',{name:'Workshop daily',scan_id:2,interval_minutes:1440});await api('baselines',{scan_id:2,note:'Current reference'});
 browser=await chromium.launch({headless:true,args:['--no-sandbox'],...(process.env.SCOPEGLASS_BROWSER?{executablePath:process.env.SCOPEGLASS_BROWSER}:{})});
 const context=await browser.newContext({viewport:{width:1440,height:1100},acceptDownloads:true});
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.waitForFunction(()=>document.getElementById('port-count').textContent==='4');
 await page.locator('summary').filter({hasText:'Save and recover'}).click();
 let download=page.waitForEvent('download');await page.click('#export');const archive=JSON.parse(fs.readFileSync(await(await download).path(),'utf8'));assert(archive.scans.length===2&&archive.schedules.length===1);const archiveFile=path.join(tmp,'backup.json');fs.writeFileSync(archiveFile,JSON.stringify(archive));
 await page.fill('#query','port:2323');await page.waitForFunction(()=>document.getElementById('port-count').textContent==='2');
 download=page.waitForEvent('download');await page.click('#csv-export');const csv=fs.readFileSync(await(await download).path(),'utf8');assert(csv.startsWith('\uFEFF'));const csvFile=path.join(tmp,'results.csv');fs.writeFileSync(csvFile,csv);
 const csvRows=JSON.parse(cp.execFileSync('python3',['-c','import csv,json,sys; print(json.dumps(list(csv.reader(open(sys.argv[1],encoding="utf-8-sig",newline="")))))',csvFile],{encoding:'utf8'}));
 assert.equal(csvRows.length,3);assert.equal(csvRows[1][2],"'=HYPERLINK(\"fixture\")");assert.equal(csvRows[1][18],"'+SUM(1,2)\nOwner: \"test\"");assert.equal(csvRows[1][14],'Response, "quoted"\nnext line');assert(csvRows.slice(1).every(row=>row[4]==='2323'));
 await page.click('#clear-filters');await page.waitForFunction(()=>document.getElementById('port-count').textContent==='4');
 const popup=page.waitForEvent('popup');await page.click('#report');const report=await popup;await report.getByRole('heading',{name:'Review summary'}).waitFor();assert((await report.textContent('body')).includes('HTTP Page title: Workshop Camera <img src=x>'));assert((await report.textContent('body')).includes('Next step:'));assert.equal(await report.locator('tbody tr').count(),4);assert.equal(await report.locator('img').count(),0);await report.pdf({path:path.join(tmp,'report.pdf'),format:'A4'});assert(fs.statSync(path.join(tmp,'report.pdf')).size>1000);await report.close();
 await manage(page);await page.click('#data-preview');await page.waitForFunction(()=>document.getElementById('data-message').textContent.includes('Choose a Scopeglass'));
 await page.setInputFiles('#restore-file',{name:'invalid.json',mimeType:'application/json',buffer:Buffer.from('{bad')});await page.click('#data-preview');await page.waitForFunction(()=>document.getElementById('data-message').textContent.includes('not valid JSON'));assert.equal((await api('data/status')).counts.scans,2);
 await page.setInputFiles('#restore-file',archiveFile);await page.click('#data-preview');await page.locator('#data-confirm-fields').waitFor({state:'visible'});assert((await page.textContent('#data-preview-result')).includes('schedules are paused'));assert(await page.locator('#data-apply').isDisabled());
 await page.screenshot({path:path.join(root,'docs','data-restore.png'),fullPage:false});
 for(const width of [320,390,768,1280]){await page.setViewportSize({width,height:900});assert(await page.locator('#data-dialog').evaluate(el=>el.scrollWidth<=el.clientWidth),'dialog overflow '+width);assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'page overflow '+width)}
 await page.setViewportSize({width:390,height:844});await page.locator('#data-dialog').evaluate(el=>el.scrollTop=0);await page.screenshot({path:path.join(root,'docs','data-mobile.png'),fullPage:false});await page.setViewportSize({width:1440,height:1100});await page.keyboard.press('Escape');assert(await page.evaluate(()=>document.activeElement.id==='manage-data'));
 await manage(page);await preview(page,'cleanup');assert((await page.textContent('#data-preview-result')).includes('Scans: 1'));await page.fill('#data-confirm','DELETE');assert(await page.locator('#data-apply').isDisabled());await page.fill('#data-confirm','DELETE OLD SCANS');await page.click('#data-apply');await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Old scans removed.'));assert.equal((await api('data/status')).counts.scans,1);assert.equal((await api('export')).assets.length,1);
 // A second tab must require a reload after a replacement, retaining its old draft separately.
 const old=await context.newPage();old.on('pageerror',e=>errors.push(e.message));await old.goto(base);await old.waitForFunction(()=>document.getElementById('port-count').textContent==='4');await old.locator('#device-list [data-inspect]').first().click();await old.waitForFunction(()=>document.getElementById('inspector').open);
 await page.evaluate(()=>{localStorage.setItem('scopeglass.draft.legacy','fixture');localStorage.setItem('scopeglass.preferences.v1',JSON.stringify({targets:'127.0.0.1',theme:'light'}))});
 await manage(page);await preview(page,'fresh');await page.fill('#data-confirm','FRESH START');await page.click('#data-apply');await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Fresh Start complete.'));await page.locator('#empty-start').waitFor();assert.equal((await api('data/status')).counts.scans,0);assert(await page.evaluate(()=>!localStorage.getItem('scopeglass.draft.legacy')));assert.equal(await page.inputValue('#targets'),'');
 await old.fill('#device-notes','Old dataset edit');await old.waitForFunction(()=>document.getElementById('inspector-save').textContent.includes('Reload'));assert.equal((await api('data/status')).counts.assets,0);
 await manage(page);await page.setInputFiles('#restore-file',archiveFile);await page.click('#data-preview');await page.locator('#data-confirm-fields').waitFor({state:'visible'});await page.fill('#data-confirm','RESTORE');await page.click('#data-apply');await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Backup restored. All schedules are paused.'));await page.waitForFunction(()=>document.getElementById('port-count').textContent==='4');
 const restored=await api('export');assert.equal(restored.scans.length,2);assert.equal(restored.assets[0].name,archive.assets[0].name);assert.equal(restored.schedules[0].enabled,0);assert.equal(fs.readdirSync(path.join(tmp,'backups')).length,3);assert((await page.textContent('#notice')).includes(path.join(tmp,'backups')));
 assert.deepEqual(errors,[]);console.log('PASS: JSON download and restore, invalid-file feedback, CSV filtering/quotes/newlines/formula protection, readable report/PDF and escaped content, restore preview and typed confirmation, cleanup protected baseline/schedule data, Fresh Start and browser settings reset, restored schedules paused, checked backup files, stale-tab write blocked, 320/390/768/1280px recovery dialog, Escape/focus return, zero JS errors');
}finally{if(browser)await browser.close();if(server)server.kill()}})().catch(e=>{console.error(e);process.exitCode=1});
