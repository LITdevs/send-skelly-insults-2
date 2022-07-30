var express  = require('express')
var fs = require('fs')
var app = express()
const { Webhook } = require('discord-webhook-node');
require("dotenv").config();
const hook = new Webhook(process.env.WEBHOOK);
const rateLimit = require("express-rate-limit");
app.use("/resources", express.static('resources'))
app.use(express.urlencoded({extended:true}));
app.use(express.json())
app.set('trust proxy', 1);
app.set('view engine', "ejs");

const messageLimiter = rateLimit({
	windowMs: 30000,
	max: 1,
	keyGenerator: function (req) {
		return req.headers["cf-connecting-ip"];
	}
});

let messageCache = [];

if (!fs.existsSync("banlist.json")) {
	fs.writeFileSync("banlist.json", JSON.stringify({banned_ips: []}));
}
let banlist = JSON.parse(fs.readFileSync("banlist.json").toString());

app.post("/api/send", messageLimiter, (req, res) => {
	if (banlist.banned_ips.includes(req.headers["cf-connecting-ip"])) return res.status(403).send("You are banned from using this service.");
	let lengthLimit = 240;
	let authorLimit = 40;
	if (!req.body.message) return res.status(400).send("No message provided.");
	if (req.body.message.trim().length > lengthLimit) return res.status(400).send("Message too long.");
	if (req.body?.author?.trim().length > authorLimit) return res.status(400).send("Author too long.");
	if (req.body.message.trim().length < 1) return res.status(400).send("Message too short.");
	let finalMessage = { message: req.body.message.trim(), ip: req.headers["cf-connecting-ip"] };
	finalMessage.title = `New insult${req.body.author ? " from " + req.body.author.trim() : ""}`;
	messageCache.push(finalMessage);
	res.redirect("/?sent=true")
})

app.get("/api/messages", (req, res) => {
	if (!req.query.auth) return res.sendStatus(403);
	if (req.query.auth !== process.env.API_KEY) return res.sendStatus(403);
	res.send(messageCache);
	messageCache = [];
})

app.post("/api/hof", (req, res) => {
	if (!req.body.auth) return res.sendStatus(403);
	if (req.body.auth !== process.env.API_KEY) return res.sendStatus(403);
	if (!req.body.message) return res.sendStatus(400);
	hook.send(req.body.message);
	res.sendStatus(200);
})

app.post("/api/ipbl", (req, res) => {
	if (!req.body.auth) return res.sendStatus(403);
	if (req.body.auth !== process.env.API_KEY) return res.sendStatus(403);
	if (!req.body.ip) return res.sendStatus(400);
	if (banlist.banned_ips.includes(req.body.ip)) return res.sendStatus(400);
	banlist.banned_ips.push(req.body.ip);
	fs.writeFileSync("banlist.json", JSON.stringify(banlist));
	res.sendStatus(200);
})

app.get("/", (req, res) => {
	res.render("index", {sent: false});
})
app.get("/?sent=true", (req, res) => {
	res.render("index", {sent: true});
})

app.listen(83, () => {
	console.log("Server started on port 83 ┌(ﾟ▽ﾟ)┘ party time");
})

