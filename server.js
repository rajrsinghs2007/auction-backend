require('dotenv').config();
const path=require('path');
const fs=require('fs');
const http=require('http');
const express=require('express');
const helmet=require('helmet');
const cookieParser=require('cookie-parser');
const cors=require('cors');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const Database=require('better-sqlite3');
const rateLimit=require('express-rate-limit');
const multer=require('multer');
const {Server}=require('socket.io');
const {z}=require('zod');

const ROOT=__dirname;
const PORT=Number(process.env.PORT||3000);
const NODE_ENV=process.env.NODE_ENV||'development';
const JWT_SECRET=process.env.JWT_SECRET;
if(NODE_ENV==='production' && JWT_SECRET && JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters when provided in production.');
const DB_PATH=process.env.DB_PATH || path.join(ROOT,'auction.db');
fs.mkdirSync(path.dirname(DB_PATH),{recursive:true});

// A deployment should provide JWT_SECRET. If it is omitted, generate and persist a
// strong secret beside the database so authentication still works after restarts.
// This is especially useful for one-click deployments; setting JWT_SECRET explicitly
// remains recommended for production secret management.
let effectiveJwtSecret=JWT_SECRET;
if(!effectiveJwtSecret){
  const secretFile=path.join(path.dirname(DB_PATH),'.jwt-secret');
  try{
    if(fs.existsSync(secretFile)) effectiveJwtSecret=fs.readFileSync(secretFile,'utf8').trim();
    if(!effectiveJwtSecret || effectiveJwtSecret.length<32){
      effectiveJwtSecret=require('crypto').randomBytes(48).toString('hex');
      fs.writeFileSync(secretFile,effectiveJwtSecret,{mode:0o600});
    }
  }catch(e){
    throw new Error('JWT_SECRET is not set and the application could not create its persistent secret: '+e.message);
  }
}
const JWT_SECRET_VALUE=effectiveJwtSecret;
const db=new Database(DB_PATH);
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
fs.mkdirSync(path.join(ROOT,'uploads'),{recursive:true});

db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,phone TEXT,role TEXT NOT NULL DEFAULT 'user',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS auctions(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,category TEXT NOT NULL,description TEXT,condition TEXT,brand TEXT,start_price REAL NOT NULL,current_price REAL NOT NULL,bid_increment REAL NOT NULL,seller_id INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'upcoming',start_at TEXT NOT NULL,end_at TEXT NOT NULL,image TEXT,location TEXT,shipping TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(seller_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS bids(id INTEGER PRIMARY KEY AUTOINCREMENT,auction_id INTEGER NOT NULL,user_id INTEGER NOT NULL,amount REAL NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(auction_id) REFERENCES auctions(id),FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS watchlist(user_id INTEGER NOT NULL,auction_id INTEGER NOT NULL,PRIMARY KEY(user_id,auction_id),FOREIGN KEY(user_id) REFERENCES users(id),FOREIGN KEY(auction_id) REFERENCES auctions(id));
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,text TEXT NOT NULL,read_at TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,auction_id INTEGER NOT NULL,buyer_id INTEGER NOT NULL,amount REAL NOT NULL,status TEXT NOT NULL DEFAULT 'pending',payment_reference TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(auction_id) REFERENCES auctions(id),FOREIGN KEY(buyer_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,email TEXT,subject TEXT,message TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);

const seed=()=>{
 if(process.env.SEED_DEMO !== 'true') return;
 let admin=db.prepare('SELECT id FROM users WHERE email=?').get('demo@auction.local');
 if(!admin){const demoPassword=process.env.DEMO_PASSWORD; if(!demoPassword || demoPassword.length < 12) throw new Error('SEED_DEMO=true requires DEMO_PASSWORD of at least 12 characters.'); const hash=bcrypt.hashSync(demoPassword,12);const r=db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run('Demo Seller','demo@auction.local',hash,'user');admin=r.lastInsertRowid;}
 if(db.prepare('SELECT COUNT(*) c FROM auctions').get().c===0){const now=Date.now();const rows=[
 ['iPhone 15 Pro 256GB','Mobiles','Premium smartphone in excellent condition','Excellent','Apple',50000,75000,1000,'live',now,now+5*3600000+23*60000,'📱','Delhi','Seller ships'],
 ['Canon EOS R10 DSLR','Electronics','Mirrorless camera body with kit lens','Like New','Canon',42000,58000,1000,'live',now,now+9*3600000,'📷','Mumbai','Seller ships'],
 ['Vintage Classic Watch','Watches','Classic mechanical collector watch','Excellent','Vintage',12000,18500,500,'live',now,now+2*3600000+18*60000,'⌚','Lucknow','Seller ships'],
 ['Gaming Console Bundle','Gaming','Console with controllers and games','Good','Sony',25000,31000,1000,'live',now,now+14*3600000,'🎮','Delhi','Seller ships'],
 ['Royal Enfield Classic 350','Vehicles','Classic motorcycle, verified papers','Good','Royal Enfield',150000,178000,2500,'upcoming',now+2*86400000,now+3*86400000,'🏍️','Lucknow','Local pickup'],
 ['Original Landscape Painting','Art','Original signed landscape painting','Excellent','Artisan',10000,22000,1000,'upcoming',now+4*86400000,now+5*86400000,'🖼️','Jaipur','Seller ships'],
 ['Vintage Indian Coin Set','Collectibles','Curated vintage Indian coin collection','Good','Collector',5000,9500,500,'live',now,now+7*3600000,'🪙','Kolkata','Seller ships'],
 ['Premium Wireless Headphones','Electronics','Wireless ANC headphones','Like New','AudioPro',6000,8200,250,'live',now,now+3*3600000,'🎧','Bengaluru','Seller ships']];
 const ins=db.prepare('INSERT INTO auctions(name,category,description,condition,brand,start_price,current_price,bid_increment,status,start_at,end_at,image,location,shipping,seller_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
 rows.forEach(x=>ins.run(...x,admin));
 }
}; seed();

function tokenFor(u){return jwt.sign({id:u.id,role:u.role,name:u.name,email:u.email},JWT_SECRET_VALUE,{expiresIn:'7d'});}
function auth(req,res,next){try{const t=req.cookies.auction_token||req.headers.authorization?.replace('Bearer ','');if(!t)return res.status(401).json({error:'Authentication required'});req.user=jwt.verify(t,JWT_SECRET_VALUE);next();}catch(e){res.status(401).json({error:'Invalid or expired session'});}}
function optionalAuth(req,res,next){try{const t=req.cookies.auction_token||req.headers.authorization?.replace('Bearer ','');req.user=t?jwt.verify(t,JWT_SECRET_VALUE):null;}catch{} next();}
function safeAuction(a,uid){return {...a,watched:!!(uid&&db.prepare('SELECT 1 FROM watchlist WHERE user_id=? AND auction_id=?').get(uid,a.id)),seller:undefined};}
function refreshStatuses(){db.prepare("UPDATE auctions SET status='ended' WHERE status IN ('live','upcoming') AND datetime(end_at)<=datetime('now')").run();db.prepare("UPDATE auctions SET status='live' WHERE status='upcoming' AND datetime(start_at)<=datetime('now') AND datetime(end_at)>datetime('now')").run();}
setInterval(refreshStatuses,30000);

const app=express();
app.disable('x-powered-by');
if(NODE_ENV==='production') app.set('trust proxy', 1);
const server=http.createServer(app);
const io=new Server(server,{cors:{origin:false}});
const allowedOrigins=(process.env.FRONTEND_URL||'').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({
  origin:(origin,cb)=>{
    if(!origin || allowedOrigins.length===0 || allowedOrigins.includes(origin)) return cb(null,true);
    cb(new Error('CORS origin not allowed'));
  },
  credentials:true
}));
app.use(helmet({contentSecurityPolicy:false})); app.use(express.json({limit:'1mb'})); app.use(express.urlencoded({extended:true})); app.use(cookieParser());
app.use('/uploads',express.static(path.join(ROOT,'uploads'))); app.use(express.static(ROOT));
const limiter=rateLimit({windowMs:15*60*1000,max:300,standardHeaders:'draft-8',legacyHeaders:false});
const authLimiter=rateLimit({windowMs:15*60*1000,max:20,standardHeaders:'draft-8',legacyHeaders:false,message:{error:'Too many authentication attempts. Please try again later.'}});
app.use('/api/',limiter);
app.use('/api/auth/login',authLimiter);
app.use('/api/auth/register',authLimiter);

app.get('/api/health',(req,res)=>res.json({ok:true,service:'AUCTION',time:new Date().toISOString()}));
app.post('/api/auth/register',async(req,res)=>{const p=z.object({name:z.string().min(2),email:z.string().email(),password:z.string().min(8),phone:z.string().optional()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:p.error.issues[0].message});try{const h=await bcrypt.hash(p.data.password,12);const r=db.prepare('INSERT INTO users(name,email,password_hash,phone) VALUES(?,?,?,?)').run(p.data.name,p.data.email.toLowerCase(),h,p.data.phone||null);const u=db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(r.lastInsertRowid);res.cookie('auction_token',tokenFor(u),{httpOnly:true,sameSite:NODE_ENV==='production'?'none':'lax',secure:NODE_ENV==='production',maxAge:7*86400000,path:'/'});res.status(201).json({user:u});}catch(e){res.status(409).json({error:'Email is already registered'});}});
app.post('/api/auth/login',async(req,res)=>{const p=z.object({email:z.string().email(),password:z.string()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Valid email and password are required'});const u=db.prepare('SELECT * FROM users WHERE email=?').get(p.data.email.toLowerCase());if(!u||!(await bcrypt.compare(p.data.password,u.password_hash)))return res.status(401).json({error:'Invalid email or password'});const safe={id:u.id,name:u.name,email:u.email,role:u.role};res.cookie('auction_token',tokenFor(safe),{httpOnly:true,sameSite:NODE_ENV==='production'?'none':'lax',secure:NODE_ENV==='production',maxAge:7*86400000,path:'/'});res.json({user:safe});});
app.post('/api/auth/logout',(req,res)=>{res.clearCookie('auction_token',{httpOnly:true,sameSite:NODE_ENV==='production'?'none':'lax',secure:NODE_ENV==='production',path:'/'});res.json({ok:true})});
app.get('/api/auth/me',auth,(req,res)=>res.json({user:req.user}));

app.get('/api/auctions',(req,res)=>{refreshStatuses();const {q,category,status,sort='newest'}=req.query;let sql='SELECT a.*,u.name seller FROM auctions a JOIN users u ON u.id=a.seller_id WHERE 1=1',args=[];if(q){sql+=' AND (a.name LIKE ? OR a.category LIKE ? OR a.description LIKE ?)';const x=`%${q}%`;args.push(x,x,x)}if(category){sql+=' AND a.category=?';args.push(category)}if(status){sql+=' AND a.status=?';args.push(status)}sql+=sort==='price'?' ORDER BY current_price ASC':sort==='highest'?' ORDER BY current_price DESC':sort==='ending'?' ORDER BY datetime(end_at) ASC':' ORDER BY datetime(created_at) DESC';const rows=db.prepare(sql).all(...args);res.json(rows.map(a=>({...a,watched:!!(req.user&&db.prepare('SELECT 1 FROM watchlist WHERE user_id=? AND auction_id=?').get(req.user.id,a.id))})));});
app.get('/api/auctions/:id',(req,res)=>{refreshStatuses();const a=db.prepare('SELECT a.*,u.name seller,u.email seller_email FROM auctions a JOIN users u ON u.id=a.seller_id WHERE a.id=?').get(req.params.id);if(!a)return res.status(404).json({error:'Auction not found'});const bids=db.prepare('SELECT b.id,b.amount,b.created_at,u.name FROM bids b JOIN users u ON u.id=b.user_id WHERE b.auction_id=? ORDER BY b.amount DESC,b.id DESC LIMIT 50').all(a.id);res.json({...a,bids});});
app.post('/api/auctions',auth,(req,res)=>{const p=z.object({name:z.string().min(3),category:z.string().min(2),description:z.string().min(5),condition:z.string().optional(),brand:z.string().optional(),startPrice:z.coerce.number().positive(),increment:z.coerce.number().positive(),startAt:z.string(),endAt:z.string(),location:z.string().optional(),shipping:z.string().optional(),image:z.string().optional()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:p.error.issues[0].message});if(new Date(p.data.endAt)<=new Date(p.data.startAt))return res.status(400).json({error:'End time must be after start time'});const status=new Date(p.data.startAt)<=new Date()?'live':'upcoming';const r=db.prepare('INSERT INTO auctions(name,category,description,condition,brand,start_price,current_price,bid_increment,status,start_at,end_at,image,location,shipping,seller_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(p.data.name,p.data.category,p.data.description,p.data.condition||'',p.data.brand||'',p.data.startPrice,p.data.startPrice,p.data.increment,status,p.data.startAt,p.data.endAt,p.data.image||'',p.data.location||'',p.data.shipping||'',req.user.id);res.status(201).json({id:r.lastInsertRowid});});
app.post('/api/auctions/:id/bids',auth,(req,res)=>{const amount=Number(req.body.amount);if(!Number.isFinite(amount))return res.status(400).json({error:'Invalid bid amount'});const result=db.transaction(()=>{const a=db.prepare('SELECT * FROM auctions WHERE id=?').get(req.params.id);if(!a)return {status:404,error:'Auction not found'};if(a.seller_id===req.user.id)return {status:403,error:'Sellers cannot bid on their own auction'};const now=new Date(),start=new Date(a.start_at),end=new Date(a.end_at);if(a.status!=='live'||now<start||now>=end)return {status:400,error:'Auction is not live'};if(amount<a.current_price+a.bid_increment)return {status:400,error:`Minimum bid is ₹${(a.current_price+a.bid_increment).toLocaleString('en-IN')}`};const r=db.prepare('INSERT INTO bids(auction_id,user_id,amount) VALUES(?,?,?)').run(a.id,req.user.id,amount);db.prepare('UPDATE auctions SET current_price=current_price+0 WHERE id=?').run(a.id);db.prepare('UPDATE auctions SET current_price=? WHERE id=?').run(amount,a.id);db.prepare('INSERT INTO notifications(user_id,text) VALUES(?,?)').run(req.user.id,`Your bid of ₹${amount.toLocaleString('en-IN')} was placed.`);return {status:201,bid:{id:r.lastInsertRowid,amount}};})();if(result.status!==201)return res.status(result.status).json({error:result.error});io.to(`auction:${req.params.id}`).emit('bid:update',result.bid);res.status(201).json(result.bid);});

app.post('/api/watchlist/:id',auth,(req,res)=>{const a=db.prepare('SELECT id FROM auctions WHERE id=?').get(req.params.id);if(!a)return res.status(404).json({error:'Auction not found'});const x=db.prepare('SELECT 1 FROM watchlist WHERE user_id=? AND auction_id=?').get(req.user.id,a.id);if(x)db.prepare('DELETE FROM watchlist WHERE user_id=? AND auction_id=?').run(req.user.id,a.id);else db.prepare('INSERT INTO watchlist(user_id,auction_id) VALUES(?,?)').run(req.user.id,a.id);res.json({watched:!x});});
app.get('/api/watchlist',auth,(req,res)=>res.json(db.prepare('SELECT a.* FROM auctions a JOIN watchlist w ON w.auction_id=a.id WHERE w.user_id=? ORDER BY w.rowid DESC').all(req.user.id)));
app.get('/api/my-bids',auth,(req,res)=>res.json(db.prepare('SELECT b.*,a.name,a.status,a.end_at FROM bids b JOIN auctions a ON a.id=b.auction_id WHERE b.user_id=? ORDER BY b.id DESC').all(req.user.id)));
app.get('/api/my-auctions',auth,(req,res)=>res.json(db.prepare('SELECT a.*,COUNT(b.id) bids FROM auctions a LEFT JOIN bids b ON b.auction_id=a.id WHERE a.seller_id=? GROUP BY a.id ORDER BY a.id DESC').all(req.user.id)));
app.get('/api/notifications',auth,(req,res)=>res.json(db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100').all(req.user.id)));
app.patch('/api/notifications/read',auth,(req,res)=>{db.prepare('UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE user_id=?').run(req.user.id);res.json({ok:true})});

const upload=multer({
  storage:multer.diskStorage({
    destination:(req,file,cb)=>cb(null,path.join(ROOT,'uploads')),
    filename:(req,file,cb)=>{
      const ext=path.extname(file.originalname).toLowerCase();
      const safeExt=['.jpg','.jpeg','.png','.webp','.gif'].includes(ext)?ext:'.img';
      cb(null,`${Date.now()}-${require('crypto').randomBytes(8).toString('hex')}${safeExt}`);
    }
  }),
  limits:{fileSize:5*1024*1024,files:8},
  fileFilter:(req,file,cb)=>cb(null,/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype))
});
app.post('/api/upload',auth,upload.array('images',8),(req,res)=>{
  if(!req.files?.length)return res.status(400).json({error:'Please select at least one valid image (JPG, PNG, WEBP or GIF).'});
  res.status(201).json({files:req.files.map(f=>`/uploads/${f.filename}`)});
});
app.use((err,req,res,next)=>{
  if(err instanceof multer.MulterError)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'Each image must be 5 MB or smaller.':err.message});
  next(err);
});
app.post('/api/contact',(req,res)=>{const p=z.object({name:z.string().min(2),email:z.string().email(),subject:z.string().min(2),message:z.string().min(5)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Please complete all contact fields'});db.prepare('INSERT INTO messages(name,email,subject,message) VALUES(?,?,?,?)').run(p.data.name,p.data.email,p.data.subject,p.data.message);res.status(201).json({ok:true});});
app.post('/api/orders',auth,(req,res)=>{const id=Number(req.body.auctionId);const a=db.prepare('SELECT * FROM auctions WHERE id=?').get(id);if(!a)return res.status(404).json({error:'Auction not found'});if(a.status!=='ended')return res.status(400).json({error:'Auction has not ended'});const winner=db.prepare('SELECT user_id,amount FROM bids WHERE auction_id=? ORDER BY amount DESC,id DESC LIMIT 1').get(id);if(!winner||winner.user_id!==req.user.id)return res.status(403).json({error:'Only the winning bidder can checkout'});const existing=db.prepare('SELECT id FROM orders WHERE auction_id=?').get(id);if(existing)return res.json(existing);const r=db.prepare('INSERT INTO orders(auction_id,buyer_id,amount,status,payment_reference) VALUES(?,?,?,?,?)').run(id,req.user.id,winner.amount,'pending','DEMO-'+Date.now());res.status(201).json({id:r.lastInsertRowid,status:'pending',amount:winner.amount});});

io.on('connection',socket=>{socket.on('auction:join',id=>socket.join(`auction:${id}`));});
app.get('*',(req,res)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'Not found'});res.sendFile(path.join(ROOT,'index.html'));});
server.listen(PORT,()=>console.log(`AUCTION running on port ${PORT} (${NODE_ENV})`));

const shutdown=()=>{console.log('Shutting down...'); server.close(()=>{db.close(); process.exit(0);});};
process.on('SIGTERM',shutdown); process.on('SIGINT',shutdown);
