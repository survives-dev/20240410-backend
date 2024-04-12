const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const fastify = require('fastify');
const app = fastify({ trustProxy: true });
const axios = require('axios');

require('dotenv').config();

const configJsonFile = fs.readFileSync('data/config.json', 'utf8');
const CONFIG = JSON.parse(configJsonFile);
const ME = [
	'<a href="https://',
	new URL(CONFIG.me).hostname,
	'/" rel="me nofollow noopener noreferrer" target="_blank">',
	'https://',
	new URL(CONFIG.me).hostname,
	'/',
	'</a>',
].join('');
let privateKeyPem = process.env.PRIVATE_KEY;
privateKeyPem = privateKeyPem.split('\\n').join('\n');
if (privateKeyPem.startsWith('"')) privateKeyPem = privateKeyPem.slice(1);
if (privateKeyPem.endsWith('"')) privateKeyPem = privateKeyPem.slice(0, -1);
const PRIVATE_KEY = privateKeyPem;
const PUBLIC_KEY = crypto.createPublicKey(PRIVATE_KEY).export({ type: 'spki', format: 'pem' });

app.register(require('@fastify/static'), { root: path.join(__dirname, 'public') });
app.addContentTypeParser(
	'application/activity+json',
	{ parseAs: 'string' },
	app.getDefaultJsonParser()
);

function talkScript(req) {
	if (new URL(req).hostname === 'localhost') return `<p>${Math.floor(Date.now() / 1000)}</p>`;
	return [
		'<p>',
		'<a href="https://',
		new URL(req).hostname,
		'/" rel="nofollow noopener noreferrer" target="_blank">',
		new URL(req).hostname,
		'</a>',
		'</p>',
	].join('');
}

async function getActivity(req) {
	const res = await axios.get(req, { headers: { Accept: 'application/activity+json' } });
	console.log(`GET ${req} ${res.status}`);
	return res.data;
}

async function postActivity(req, body, headers) {
	console.log(`POST ${req} ${JSON.stringify(body)}`);
	await axios.post(req, JSON.stringify(body), { headers });
}

function signHeaders(body, strName, strHost, strInbox) {
	const strTime = new Date().toUTCString();
	const s256 = crypto.createHash('sha256').update(JSON.stringify(body)).digest('base64');
	const sig = crypto
		.createSign('sha256')
		.update(
			[
				`(request-target): post ${new URL(strInbox).pathname}`,
				`host: ${new URL(strInbox).hostname}`,
				`date: ${strTime}`,
				`digest: SHA-256=${s256}`,
			].join('\n')
		)
		.end();
	const b64 = sig.sign(PRIVATE_KEY, 'base64');
	const headers = {
		Host: new URL(strInbox).hostname,
		Date: strTime,
		Digest: `SHA-256=${s256}`,
		Signature: [
			`keyId="https://${strHost}/u/${strName}#Key"`,
			'algorithm="rsa-sha256"',
			'headers="(request-target) host date digest"',
			`signature="${b64}"`,
		].join(),
		Accept: 'application/json',
		'Accept-Encoding': 'gzip',
		'Cache-Control': 'max-age=0',
		'Content-Type': 'application/activity+json',
		'User-Agent': `StrawberryFields-Fastify/2.8.0 (+https://${strHost}/)`,
	};
	return headers;
}

async function acceptFollow(strName, strHost, x, y) {
	const numId = Math.floor(Date.now() / 1000);
	const strInbox = x.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}`,
		type: 'Accept',
		actor: `https://${strHost}/u/${strName}`,
		object: y,
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function follow(strName, strHost, x) {
	const numId = Math.floor(Date.now() / 1000);
	const strInbox = x.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}`,
		type: 'Follow',
		actor: `https://${strHost}/u/${strName}`,
		object: x.id,
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function undoFollow(strName, strHost, x) {
	const numId = Math.floor(Date.now() / 1000);
	const strInbox = x.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}#Undo`,
		type: 'Undo',
		actor: `https://${strHost}/u/${strName}`,
		object: {
			id: `https://${strHost}/u/${strName}/s/${numId}`,
			type: 'Follow',
			actor: `https://${strHost}/u/${strName}`,
			object: x.id,
		},
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function like(strName, strHost, x, y) {
	const numId = Math.floor(Date.now() / 1000);
	const strInbox = y.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}`,
		type: 'Like',
		actor: `https://${strHost}/u/${strName}`,
		object: x.id,
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function undoLike(strName, strHost, x, y) {
	const numId = Math.floor(Date.now() / 1000);
	const strInbox = y.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}#Undo`,
		type: 'Undo',
		actor: `https://${strHost}/u/${strName}`,
		object: {
			id: `https://${strHost}/u/${strName}/s/${numId}`,
			type: 'Like',
			actor: `https://${strHost}/u/${strName}`,
			object: x.id,
		},
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function announce(strName, strHost, x, y) {
	const numId = Math.floor(Date.now() / 1000);
	const strTime = new Date().toISOString().substring(0, 19) + 'Z';
	const strInbox = y.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}`,
		type: 'Announce',
		actor: `https://${strHost}/u/${strName}`,
		published: strTime,
		to: ['https://www.w3.org/ns/activitystreams#Public'],
		cc: [`https://${strHost}/u/${strName}/followers`],
		object: x.id,
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function undoAnnounce(strName, strHost, x, y) {
	const numId = Math.floor(Date.now() / 1000);
	const strInbox = y.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}#Undo`,
		type: 'Undo',
		actor: `https://${strHost}/u/${strName}`,
		object: {
			id: `https://${strHost}/u/${strName}/s/${numId}`,
			type: 'Announce',
			actor: `https://${strHost}/u/${strName}`,
			object: x.id,
		},
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function createNote(strName, strHost, x, y) {
	const numId = Math.floor(Date.now() / 1000);
	const strTime = new Date().toISOString().substring(0, 19) + 'Z';
	const strInbox = x.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}/activity`,
		type: 'Create',
		actor: `https://${strHost}/u/${strName}`,
		published: strTime,
		to: ['https://www.w3.org/ns/activitystreams#Public'],
		cc: [`https://${strHost}/u/${strName}/followers`],
		object: {
			id: `https://${strHost}/u/${strName}/s/${numId}`,
			type: 'Note',
			attributedTo: `https://${strHost}/u/${strName}`,
			content: talkScript(y),
			url: `https://${strHost}/u/${strName}/s/${numId}`,
			published: strTime,
			to: ['https://www.w3.org/ns/activitystreams#Public'],
			cc: [`https://${strHost}/u/${strName}/followers`],
		},
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function createNoteMention(strName, strHost, x, y, z) {
	const numId = Math.floor(Date.now() / 1000);
	const strTime = new Date().toISOString().substring(0, 19) + 'Z';
	const strInbox = y.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}/activity`,
		type: 'Create',
		actor: `https://${strHost}/u/${strName}`,
		published: strTime,
		to: ['https://www.w3.org/ns/activitystreams#Public'],
		cc: [`https://${strHost}/u/${strName}/followers`],
		object: {
			id: `https://${strHost}/u/${strName}/s/${numId}`,
			type: 'Note',
			attributedTo: `https://${strHost}/u/${strName}`,
			inReplyTo: x.id,
			content: talkScript(z),
			url: `https://${strHost}/u/${strName}/s/${numId}`,
			published: strTime,
			to: ['https://www.w3.org/ns/activitystreams#Public'],
			cc: [`https://${strHost}/u/${strName}/followers`],
			tag: [
				{
					type: 'Mention',
					name: `@${y.preferredUsername}@${new URL(strInbox).hostname}`,
				},
			],
		},
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function createNoteImage(strName, strHost, x, y) {
	const numId = Math.floor(Date.now() / 1000);
	const strTime = new Date().toISOString().substring(0, 19) + 'Z';
	const strInbox = x.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}/activity`,
		type: 'Create',
		actor: `https://${strHost}/u/${strName}`,
		published: strTime,
		to: ['https://www.w3.org/ns/activitystreams#Public'],
		cc: [`https://${strHost}/u/${strName}/followers`],
		object: {
			id: `https://${strHost}/u/${strName}/s/${numId}`,
			type: 'Note',
			attributedTo: `https://${strHost}/u/${strName}`,
			content: talkScript('https://localhost'),
			url: `https://${strHost}/u/${strName}/s/${numId}`,
			published: strTime,
			to: ['https://www.w3.org/ns/activitystreams#Public'],
			cc: [`https://${strHost}/u/${strName}/followers`],
			attachment: [
				{
					type: 'Image',
					mediaType: 'image/png',
					url: y,
				},
			],
		},
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function createNoteHashtag(strName, strHost, x, y, z) {
	const numId = Math.floor(Date.now() / 1000);
	const strTime = new Date().toISOString().substring(0, 19) + 'Z';
	const strInbox = x.inbox;
	const body = {
		'@context': ['https://www.w3.org/ns/activitystreams', { Hashtag: 'as:Hashtag' }],
		id: `https://${strHost}/u/${strName}/s/${numId}/activity`,
		type: 'Create',
		actor: `https://${strHost}/u/${strName}`,
		published: strTime,
		to: ['https://www.w3.org/ns/activitystreams#Public'],
		cc: [`https://${strHost}/u/${strName}/followers`],
		object: {
			id: `https://${strHost}/u/${strName}/s/${numId}`,
			type: 'Note',
			attributedTo: `https://${strHost}/u/${strName}`,
			content: talkScript(y),
			url: `https://${strHost}/u/${strName}/s/${numId}`,
			published: strTime,
			to: ['https://www.w3.org/ns/activitystreams#Public'],
			cc: [`https://${strHost}/u/${strName}/followers`],
			tag: [
				{
					type: 'Hashtag',
					name: `#${z}`,
				},
			],
		},
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

async function deleteNote(strName, strHost, x, y) {
	const numId = Math.floor(Date.now() / 1000);
	const strInbox = x.inbox;
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/s/${numId}/activity`,
		type: 'Delete',
		actor: `https://${strHost}/u/${strName}`,
		object: {
			id: y,
			type: 'Note',
			attributedTo: `https://${strHost}/u/${strName}`,
		},
	};
	const headers = signHeaders(body, strName, strHost, strInbox);
	await postActivity(strInbox, body, headers);
}

app.get('/', (_req, res) => res.type('text/plain; charset=utf-8').send('StrawberryFields Fastify'));

app.get('/u/:strName', (req, res) => {
	const strName = req.params.strName;
	const strHost = req.hostname.split(':')[0];
	if (strName !== CONFIG.preferredUsername) return res.callNotFound();
	if (!req.headers['accept'].includes('application/activity+json')) {
		return res.type('text/plain; charset=utf-8').send(`${strName}: ${CONFIG.name}`);
	}
	const body = {
		'@context': [
			'https://www.w3.org/ns/activitystreams',
			'https://w3id.org/security/v1',
			{
				schema: 'https://schema.org/',
				PropertyValue: 'schema:PropertyValue',
				value: 'schema:value',
				Key: 'sec:Key',
			},
		],
		id: `https://${strHost}/u/${strName}`,
		type: 'Person',
		inbox: `https://${strHost}/u/${strName}/inbox`,
		outbox: `https://${strHost}/u/${strName}/outbox`,
		following: `https://${strHost}/u/${strName}/following`,
		followers: `https://${strHost}/u/${strName}/followers`,
		preferredUsername: strName,
		name: CONFIG.name,
		summary: '<p>2.8.0</p>',
		url: `https://${strHost}/u/${strName}`,
		endpoints: { sharedInbox: `https://${strHost}/u/${strName}/inbox` },
		attachment: [
			{
				type: 'PropertyValue',
				name: 'me',
				value: ME,
			},
		],
		icon: {
			type: 'Image',
			mediaType: 'image/png',
			url: `https://${strHost}/public/${strName}u.png`,
		},
		image: {
			type: 'Image',
			mediaType: 'image/png',
			url: `https://${strHost}/public/${strName}s.png`,
		},
		publicKey: {
			id: `https://${strHost}/u/${strName}#Key`,
			type: 'Key',
			owner: `https://${strHost}/u/${strName}`,
			publicKeyPem: PUBLIC_KEY,
		},
	};
	res.type('application/activity+json').send(body);
});

app.get('/u/:strName/inbox', async (_req, res) => res.code(405).send(new Error(res.statusCode)));
app.post('/u/:strName/inbox', async (req, res) => {
	const strName = req.params.strName;
	const strHost = req.hostname.split(':')[0];
	const y = req.body;
	console.log(`INBOX ${y.id} ${y.type}`);
	if (strName !== CONFIG.preferredUsername) return res.callNotFound();
	if (!req.headers['content-type'].includes('application/activity+json')) {
		return res.code(400).send(new Error(res.statusCode));
	}
	if (!req.headers['digest'] || !req.headers['signature'])
		return res.code(400).send(new Error(res.statusCode));
	if (y.type === 'Accept' || y.type === 'Reject' || y.type === 'Add')
		return res.code(200).raw.end();
	if (y.type === 'Remove' || y.type === 'Like' || y.type === 'Announce')
		return res.code(200).raw.end();
	if (y.type === 'Create' || y.type === 'Update' || y.type === 'Delete')
		return res.code(200).raw.end();
	if (y.type === 'Follow') {
		if (new URL(y.actor || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		const x = await getActivity(y.actor);
		if (!x) return res.code(500).send(new Error(res.statusCode));
		await acceptFollow(strName, strHost, x, y);
		return res.code(200).raw.end();
	}
	if (y.type === 'Undo') {
		const z = y.object;
		if (z.type === 'Accept' || z.type === 'Like' || z.type === 'Announce')
			return res.code(200).raw.end();
		if (z.type === 'Follow') {
			if (new URL(y.actor || 'about:blank').protocol !== 'https:')
				return res.code(400).send(new Error(res.statusCode));
			const x = await getActivity(y.actor);
			if (!x) return res.code(500).send(new Error(res.statusCode));
			await acceptFollow(strName, strHost, x, z);
			return res.code(200).raw.end();
		}
	}
	res.code(500).send(new Error(res.statusCode));
});

app.post('/u/:strName/outbox', (_req, res) => res.code(405).send(new Error(res.statusCode)));
app.get('/u/:strName/outbox', (req, res) => {
	const strName = req.params.strName;
	const strHost = req.hostname.split(':')[0];
	if (strName !== CONFIG.preferredUsername) return res.callNotFound();
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/outbox`,
		type: 'OrderedCollection',
		totalItems: 0,
	};
	res.type('application/activity+json').send(body);
});

app.get('/u/:strName/following', (req, res) => {
	const strName = req.params.strName;
	const strHost = req.hostname.split(':')[0];
	if (strName !== CONFIG.preferredUsername) return res.callNotFound();
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/following`,
		type: 'OrderedCollection',
		totalItems: 0,
	};
	res.type('application/activity+json').send(body);
});

app.get('/u/:strName/followers', (req, res) => {
	const strName = req.params.strName;
	const strHost = req.hostname.split(':')[0];
	if (strName !== CONFIG.preferredUsername) return res.callNotFound();
	const body = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: `https://${strHost}/u/${strName}/followers`,
		type: 'OrderedCollection',
		totalItems: 0,
	};
	res.type('application/activity+json').send(body);
});

app.post('/s/:strSecret/u/:strName', async (req, res) => {
	const strName = req.params.strName;
	const strHost = req.hostname.split(':')[0];
	const t = req.query.type;
	if (strName !== CONFIG.preferredUsername) return res.callNotFound();
	if (!req.params.strSecret || req.params.strSecret === '-') return res.callNotFound();
	if (req.params.strSecret !== process.env.SECRET) return res.callNotFound();
	if (new URL(req.query.id || 'about:blank').protocol !== 'https:')
		return res.code(400).send(new Error(res.statusCode));
	const x = await getActivity(req.query.id);
	if (!x) return res.code(500).send(new Error(res.statusCode));
	if (t === 'follow') {
		await follow(strName, strHost, x);
		return res.code(200).raw.end();
	}
	if (t === 'undo_follow') {
		await undoFollow(strName, strHost, x);
		return res.code(200).raw.end();
	}
	if (t === 'like') {
		if (new URL(x.attributedTo || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		const y = await getActivity(x.attributedTo);
		if (!y) return res.code(500).send(new Error(res.statusCode));
		await like(strName, strHost, x, y);
		return res.code(200).raw.end();
	}
	if (t === 'undo_like') {
		if (new URL(x.attributedTo || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		const y = await getActivity(x.attributedTo);
		if (!y) return res.code(500).send(new Error(res.statusCode));
		await undoLike(strName, strHost, x, y);
		return res.code(200).raw.end();
	}
	if (t === 'announce') {
		if (new URL(x.attributedTo || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		const y = await getActivity(x.attributedTo);
		if (!y) return res.code(500).send(new Error(res.statusCode));
		await announce(strName, strHost, x, y);
		return res.code(200).raw.end();
	}
	if (t === 'undo_announce') {
		if (new URL(x.attributedTo || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		const y = await getActivity(x.attributedTo);
		if (!y) return res.code(500).send(new Error(res.statusCode));
		await undoAnnounce(strName, strHost, x, y);
		return res.code(200).raw.end();
	}
	if (t === 'create_note') {
		const y = req.query.url || 'https://localhost';
		if (new URL(y || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		await createNote(strName, strHost, x, y);
		return res.code(200).raw.end();
	}
	if (t === 'create_note_image') {
		const y = req.query.url || `https://${strHost}/public/logo.png`;
		if (new URL(y || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		if (new URL(y || 'about:blank').hostname !== strHost)
			return res.code(400).send(new Error(res.statusCode));
		await createNoteImage(strName, strHost, x, y);
		return res.code(200).raw.end();
	}
	if (t === 'create_note_mention') {
		if (new URL(x.attributedTo || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		const y = await getActivity(x.attributedTo);
		if (!y) return res.code(500).send(new Error(res.statusCode));
		const z = req.query.url || 'https://localhost';
		if (new URL(z || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		await createNoteMention(strName, strHost, x, y, z);
		return res.code(200).raw.end();
	}
	if (t === 'create_note_hashtag') {
		const y = req.query.url || 'https://localhost';
		if (new URL(y || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		const z = req.query.tag || 'Hashtag';
		await createNoteHashtag(strName, strHost, x, y, z);
		return res.code(200).raw.end();
	}
	if (t === 'delete_note') {
		const y = req.query.url || `https://${strHost}/u/${strName}/s/0`;
		if (new URL(y || 'about:blank').protocol !== 'https:')
			return res.code(400).send(new Error(res.statusCode));
		await deleteNote(strName, strHost, x, y);
		return res.code(200).raw.end();
	}
	console.log(`TYPE ${x.id} ${x.type}`);
	res.code(200).raw.end();
});

app.get('/.well-known/webfinger', (req, res) => {
	const strName = CONFIG.preferredUsername;
	const strHost = req.hostname.split(':')[0];
	const strResource = req.query.resource;
	let boolResource = false;
	if (strResource === `acct:${strName}@${strHost}`) boolResource = true;
	if (strResource === `mailto:${strName}@${strHost}`) boolResource = true;
	if (strResource === `https://${strHost}/@${strName}`) boolResource = true;
	if (strResource === `https://${strHost}/u/${strName}`) boolResource = true;
	if (strResource === `https://${strHost}/user/${strName}`) boolResource = true;
	if (strResource === `https://${strHost}/users/${strName}`) boolResource = true;
	if (!boolResource) return res.callNotFound();
	const body = {
		subject: `acct:${strName}@${strHost}`,
		aliases: [
			`mailto:${strName}@${strHost}`,
			`https://${strHost}/@${strName}`,
			`https://${strHost}/u/${strName}`,
			`https://${strHost}/user/${strName}`,
			`https://${strHost}/users/${strName}`,
		],
		links: [
			{
				rel: 'self',
				type: 'application/activity+json',
				href: `https://${strHost}/u/${strName}`,
			},
			{
				rel: 'http://webfinger.net/rel/avatar',
				type: 'image/png',
				href: `https://${strHost}/public/${strName}u.png`,
			},
			{
				rel: 'http://webfinger.net/rel/profile-page',
				type: 'text/plain',
				href: `https://${strHost}/u/${strName}`,
			},
		],
	};
	res.type('application/jrd+json').send(body);
});

app.get('/@', (_req, res) => res.redirect('/'));
app.get('/u', (_req, res) => res.redirect('/'));
app.get('/user', (_req, res) => res.redirect('/'));
app.get('/users', (_req, res) => res.redirect('/'));

app.get('/users/:strName', (req, res) => res.redirect(`/u/${req.params.strName}`));
app.get('/user/:strName', (req, res) => res.redirect(`/u/${req.params.strName}`));
app.get('/@:strName', (req, res) => res.redirect(`/u/${req.params.strName}`));

app.listen({ port: process.env.PORT || 8080, host: process.env.HOSTS || 'localhost' });
