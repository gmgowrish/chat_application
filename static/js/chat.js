// End-to-end encrypted chat client.
//
// Crypto design (Web Crypto API, everything happens in the browser):
//   * Identity: one ECDH P-256 key pair per browser, created non-extractable and kept
//     in IndexedDB, so a refresh keeps the same key (and your verified status).
//   * Pairwise keys: ECDH shared secret -> HKDF-SHA-256 (bound to both public keys)
//     -> AES-256-GCM. Each message is encrypted separately for every recipient.
//   * The AAD binds sender and recipient keys (no re-routing or reflection by the
//     server); a random message id + timestamp window stop replays.
//   * Files are encrypted with a fresh AES-256-GCM key; the server stores only the
//     ciphertext for an hour. The file key travels inside the E2EE message.
//   * Verification: both people compare 8 emoji (or 60 digits) derived from both
//     public keys. Keys are pinned per name; a change raises a warning.

"use strict";

const PROTOCOL = "e2ee-chat-v2";
const MAX_MESSAGE_LENGTH = 2000;
const MAX_MESSAGE_AGE_MS = 65 * 60 * 1000; // server mailbox keeps ciphertext for 1 h
const GROUP_WINDOW_MS = 3 * 60 * 1000;
const SAFE_IMAGES = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif"];
const SAFE_VIDEOS = ["video/mp4", "video/webm", "video/ogg", "video/quicktime"];
const GENDER_SYMBOL = { male: "♂", female: "♀", transgender: "⚧", unspecified: "" };
const GENDER_LABEL = { male: "Male", female: "Female", transgender: "Transgender", unspecified: "" };
// 64 easy-to-say emoji (same idea as Matrix/Element emoji verification).
const EMOJI = [
	["🐶", "Dog"], ["🐱", "Cat"], ["🦁", "Lion"], ["🐎", "Horse"], ["🦄", "Unicorn"], ["🐷", "Pig"], ["🐘", "Elephant"], ["🐰", "Rabbit"],
	["🐼", "Panda"], ["🐓", "Rooster"], ["🐧", "Penguin"], ["🐢", "Turtle"], ["🐟", "Fish"], ["🐙", "Octopus"], ["🦋", "Butterfly"], ["🌷", "Flower"],
	["🌳", "Tree"], ["🌵", "Cactus"], ["🍄", "Mushroom"], ["🌏", "Globe"], ["🌙", "Moon"], ["☁️", "Cloud"], ["🔥", "Fire"], ["🍌", "Banana"],
	["🍎", "Apple"], ["🍓", "Strawberry"], ["🌽", "Corn"], ["🍕", "Pizza"], ["🎂", "Cake"], ["❤️", "Heart"], ["😀", "Smiley"], ["🤖", "Robot"],
	["🎩", "Hat"], ["👓", "Glasses"], ["🔧", "Spanner"], ["🎅", "Santa"], ["👍", "Thumbs up"], ["☂️", "Umbrella"], ["⌛", "Hourglass"], ["⏰", "Clock"],
	["🎁", "Gift"], ["💡", "Light bulb"], ["📕", "Book"], ["✏️", "Pencil"], ["📎", "Paperclip"], ["✂️", "Scissors"], ["🔒", "Lock"], ["🔑", "Key"],
	["🔨", "Hammer"], ["☎️", "Telephone"], ["🏁", "Flag"], ["🚂", "Train"], ["🚲", "Bicycle"], ["✈️", "Aeroplane"], ["🚀", "Rocket"], ["🏆", "Trophy"],
	["⚽", "Ball"], ["🎸", "Guitar"], ["🎺", "Trumpet"], ["🔔", "Bell"], ["⚓", "Anchor"], ["🎧", "Headphones"], ["📁", "Folder"], ["📌", "Pin"],
];

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ small utils

function toBase64(buffer) {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
	return btoa(binary);
}

function fromBase64(text) {
	return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function randomToken(bytes = 32) {
	return toBase64(crypto.getRandomValues(new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const store = {
	get(key, fallback = null) {
		try {
			const raw = localStorage.getItem(`chat.${key}`);
			return raw === null ? fallback : JSON.parse(raw);
		} catch {
			return fallback;
		}
	},
	set(key, value) {
		try {
			localStorage.setItem(`chat.${key}`, JSON.stringify(value));
		} catch {
			/* storage disabled: works for this session only */
		}
	},
};

function formatBytes(n) {
	if (n < 1024) return `${n} B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
	return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function clock(ts) {
	return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function lastSeen(ts) {
	if (!ts) return "Away";
	const minutes = Math.round((Date.now() - ts) / 60000);
	if (minutes < 1) return "Last seen just now";
	if (minutes < 60) return `Last seen ${minutes} min ago`;
	const hours = Math.round(minutes / 60);
	return `Last seen ${hours} h ago`;
}

function svgIcon(name) {
	const ns = "http://www.w3.org/2000/svg";
	const svg = document.createElementNS(ns, "svg");
	const use = document.createElementNS(ns, "use");
	use.setAttribute("href", `#i-${name}`);
	svg.append(use);
	return svg;
}

function el(tag, className, text) {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (text !== undefined) node.textContent = text;
	return node;
}

function avatar(person, size = "", online = false) {
	const gender = GENDER_SYMBOL[person.gender] !== undefined ? person.gender : "unspecified";
	const node = el("span", `avatar ${size} g-${gender}`.trim(), (person.username || "?").trim()[0] || "?");
	if (GENDER_SYMBOL[gender]) {
		const badge = el("span", `gbadge ${gender}`, GENDER_SYMBOL[gender]);
		badge.title = GENDER_LABEL[gender];
		node.append(badge);
	}
	if (online) node.append(el("span", "presence"));
	return node;
}

function toast(message, type = "info") {
	const node = el("div", `toast ${type}`, message);
	$("toasts").append(node);
	setTimeout(() => node.remove(), 4200);
}

// ------------------------------------------------------------------ crypto

function openKeyStore() {
	return new Promise((resolve, reject) => {
		const request = indexedDB.open("python-chat", 1);
		request.onupgradeneeded = () => request.result.createObjectStore("keys");
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error);
	});
}

async function loadIdentityKey() {
	const generate = () => crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
	try {
		const db = await openKeyStore();
		const read = () => new Promise((resolve, reject) => {
			const req = db.transaction("keys").objectStore("keys").get("identity");
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		let keyPair = await read();
		if (!keyPair) {
			keyPair = await generate();
			await new Promise((resolve, reject) => {
				const tx = db.transaction("keys", "readwrite");
				tx.objectStore("keys").put(keyPair, "identity");
				tx.oncomplete = resolve;
				tx.onerror = () => reject(tx.error);
			});
		}
		return keyPair;
	} catch {
		return generate(); // private mode without IndexedDB: key lasts for this tab only
	}
}

function associatedData(senderKey, recipientKey) {
	return encoder.encode(`${PROTOCOL}|from:${senderKey}|to:${recipientKey}`);
}

async function fingerprint(keyA, keyB) {
	const [first, second] = [keyA, keyB].sort();
	return new Uint8Array(await crypto.subtle.digest("SHA-512", new Uint8Array([...fromBase64(first), ...fromBase64(second)])));
}

function emojiCode(digest) {
	// 8 emoji × 6 bits = 48 bits taken from the fingerprint
	let bits = 0n;
	for (let i = 0; i < 6; i++) bits = (bits << 8n) | BigInt(digest[i]);
	return Array.from({ length: 8 }, (_, i) => EMOJI[Number((bits >> BigInt(42 - i * 6)) & 63n)]);
}

function numberCode(digest) {
	const view = new DataView(digest.buffer);
	const groups = [];
	for (let i = 0; i < 12; i++) groups.push(String(view.getUint32(i * 4) % 100000).padStart(5, "0"));
	return [0, 4, 8].map((i) => groups.slice(i, i + 4).join("  ")).join("\n");
}

// ------------------------------------------------------------------ app

async function main() {
	const ui = {
		app: document.querySelector(".app"),
		messages: $("messages"),
		empty: $("empty-state"),
		input: $("message-input"),
		send: $("send-button"),
		attach: $("attach-button"),
		attachMenu: $("attach-menu"),
		people: $("people"),
		peopleAway: $("people-away"),
		awayTitle: $("away-title"),
		peopleEmpty: $("people-empty"),
		onlineCount: $("online-count"),
		roomSub: $("room-sub"),
		stack: $("avatar-stack"),
		pill: $("e2ee-pill"),
		typing: $("typing"),
	};

	setupTheme();
	setupDialogs();

	if (!window.crypto?.subtle) {
		ui.roomSub.textContent = "Encryption needs HTTPS (or localhost).";
		toast("This page must be opened over HTTPS for encryption to work.", "error");
		return;
	}

	const keyPair = await loadIdentityKey();
	const myKey = toBase64(await crypto.subtle.exportKey("raw", keyPair.publicKey));

	let token = store.get("token");
	if (!token) {
		token = randomToken();
		store.set("token", token);
	}
	let profile = store.get("profile"); // { username, gender }
	let returning = Boolean(profile); // known person: never announce "joined" again

	let me = null;
	let maxFileBytes = 15 * 1024 * 1024;
	const roster = new Map(); // id -> { id, username, gender, public_key, online, last_seen }
	const pairKeys = new Map();
	const seen = new Set();
	const typingUntil = new Map();
	const warnedChanges = new Set();
	let lastRendered = null; // { from, ts } for message grouping
	let incoming = Promise.resolve();
	let outgoing = Promise.resolve();
	let socket = null;

	// ---------------- trust: pins (name -> key) and verified keys

	const pins = store.get("pins", {});
	const verified = store.get("verified", {});
	const savePins = () => store.set("pins", pins);
	const saveVerified = () => store.set("verified", verified);

	function trustState(person) {
		if (pins[person.username] && pins[person.username] !== person.public_key) return "changed";
		return verified[person.public_key] ? "verified" : "unverified";
	}

	function checkPin(person) {
		if (!person.public_key) return;
		const pinned = pins[person.username];
		if (!pinned) {
			pins[person.username] = person.public_key;
			savePins();
		} else if (pinned !== person.public_key && !warnedChanges.has(`${person.username}|${person.public_key}`)) {
			warnedChanges.add(`${person.username}|${person.public_key}`);
			addSystem(`${person.username}'s safety number changed. Verify them again before sharing anything private.`, true);
		}
	}

	function pairKey(person) {
		const cacheKey = person.public_key;
		if (!pairKeys.has(cacheKey)) {
			pairKeys.set(cacheKey, (async () => {
				const peer = await crypto.subtle.importKey("raw", fromBase64(person.public_key), { name: "ECDH", namedCurve: "P-256" }, false, []);
				const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, keyPair.privateKey, 256);
				const hkdf = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
				const [a, b] = [myKey, person.public_key].sort();
				return crypto.subtle.deriveKey(
					{ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: encoder.encode(`${PROTOCOL}|${a}|${b}`) },
					hkdf,
					{ name: "AES-GCM", length: 256 },
					false,
					["encrypt", "decrypt"]
				);
			})());
		}
		return pairKeys.get(cacheKey);
	}

	// ---------------- onboarding

	function askProfile(errorText = "") {
		const form = $("onboard-form");
		$("onboard").hidden = false;
		$("onboard-error").textContent = errorText;
		$("onboard-name").value = profile?.username || "";
		const gender = profile?.gender || "";
		form.querySelectorAll('input[name="onboard-gender"]').forEach((r) => (r.checked = r.value === gender));
		$("onboard-name").focus();
	}

	$("onboard-form").addEventListener("submit", (event) => {
		event.preventDefault();
		const username = $("onboard-name").value.trim();
		const gender = document.querySelector('input[name="onboard-gender"]:checked')?.value;
		if (!/^[A-Za-z0-9_\- ]{2,24}$/.test(username)) {
			$("onboard-error").textContent = "Use 2–24 letters, digits, spaces, _ or -.";
			return;
		}
		if (!gender) {
			$("onboard-error").textContent = "Please choose one option.";
			return;
		}
		profile = { username, gender };
		store.set("profile", profile);
		$("onboard").hidden = true;
		connect();
	});

	// ---------------- rendering: people

	function personRow(person) {
		const li = document.createElement("li");
		const button = el("button", "person");
		button.type = "button";
		button.title = `Verify ${person.username}`;
		const text = el("span", "person-text");
		text.append(el("span", "person-name", person.username));
		const trust = trustState(person);
		let status;
		if (person.online && (typingUntil.get(person.id) || 0) > Date.now()) {
			status = el("span", "person-status is-typing");
			const dots = el("span", "dots");
			dots.append(el("i"), el("i"), el("i"));
			status.append(dots, document.createTextNode("typing"));
		} else if (trust === "changed") {
			status = el("span", "person-status changed");
			status.append(svgIcon("warn"), document.createTextNode("Safety number changed"));
		} else if (trust === "verified") {
			status = el("span", "person-status verified");
			status.append(svgIcon("shield-check"), document.createTextNode(person.online ? "Verified" : `Verified · ${lastSeen(person.last_seen)}`));
		} else {
			status = el("span", "person-status");
			status.append(svgIcon("shield"), document.createTextNode(person.online ? "Tap to verify" : lastSeen(person.last_seen)));
		}
		text.append(status);
		button.append(avatar(person, "", person.online), text);
		button.addEventListener("click", () => {
			ui.app.classList.remove("drawer-open");
			openVerify(person.id);
		});
		li.append(button);
		return li;
	}

	function renderPeople() {
		const everyone = [...roster.values()].sort((a, b) => a.username.localeCompare(b.username));
		const online = everyone.filter((p) => p.online);
		const away = everyone.filter((p) => !p.online).sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
		ui.people.replaceChildren(...online.map(personRow));
		ui.peopleAway.replaceChildren(...away.map(personRow));
		ui.awayTitle.hidden = away.length === 0;
		ui.peopleEmpty.hidden = online.length > 0;
		ui.onlineCount.textContent = online.length + (me ? 1 : 0);

		const total = online.length + 1;
		ui.roomSub.textContent = socket?.connected
			? `${total} online · end-to-end encrypted`
			: "Reconnecting…";
		const shown = online.slice(0, 4).map((p) => avatar(p, "sm"));
		if (online.length > 4) shown.push(el("span", "avatar sm more", `+${online.length - 4}`));
		ui.stack.replaceChildren(...shown);

		const typers = online.filter((p) => (typingUntil.get(p.id) || 0) > Date.now());
		if (typers.length) {
			const dots = el("span", "dots");
			dots.append(el("i"), el("i"), el("i"));
			const names = typers.map((p) => p.username);
			const label = names.length === 1 ? `${names[0]} is typing…` : `${names.slice(0, 2).join(" and ")}${names.length > 2 ? " and others" : ""} are typing…`;
			ui.typing.replaceChildren(dots, document.createTextNode(label));
		} else {
			ui.typing.replaceChildren();
		}
	}

	function renderMe() {
		if (!me) return;
		$("me-avatar").replaceWith(Object.assign(avatar(me, "", true), { id: "me-avatar" }));
		$("me-name").textContent = me.username;
		$("me-sub").textContent = GENDER_LABEL[me.gender] ? `${GENDER_LABEL[me.gender]} · Edit profile` : "Edit profile";
	}

	// ---------------- rendering: messages

	function hideEmpty() {
		ui.empty.hidden = true;
	}

	function scrollToEnd() {
		ui.messages.scrollTop = ui.messages.scrollHeight;
	}

	function addSystem(text, warn = false) {
		hideEmpty();
		const row = el("div", warn ? "system warn" : "system");
		row.append(el("span", "", text));
		ui.messages.append(row);
		lastRendered = null;
		scrollToEnd();
	}

	function addMessage({ from, ts, text, file, outgoing: isOut, localUrl }) {
		hideEmpty();
		const sender = isOut ? me : roster.get(from) || { username: "Unknown", gender: "unspecified" };
		const grouped = lastRendered && lastRendered.from === from && ts - lastRendered.ts < GROUP_WINDOW_MS;
		lastRendered = { from, ts };

		const row = el("div", `msg${isOut ? " out" : ""}${grouped ? " grouped" : ""}`);
		const bubble = el("div", "bubble");
		bubble.append(el("div", "author", sender.username));
		if (file) bubble.append(renderAttachment(file, localUrl));
		if (text) bubble.append(el("div", "text", text));
		const meta = el("div", "meta");
		meta.append(el("span", "", clock(ts)));
		const ticks = el("span", "ticks", isOut ? "🕓" : "");
		if (isOut) meta.append(ticks);
		bubble.append(meta);
		row.append(avatar(sender, "sm"), bubble);
		ui.messages.append(row);
		scrollToEnd();
		return { row, bubble, ticks };
	}

	function setTicks(ticks, result) {
		if (!result?.ok) {
			ticks.textContent = "⚠";
			ticks.title = result?.error || "Not sent";
		} else if (result.delivered > 0) {
			ticks.textContent = "✓✓";
			ticks.title = `Delivered to ${result.delivered} online${result.queued ? `, ${result.queued} will get it when back` : ""}`;
		} else {
			ticks.textContent = "✓";
			ticks.title = "Sent. Delivered when they come back online";
		}
	}

	const fileCache = new Map(); // file id -> Promise<object URL>

	function decryptFile(file) {
		if (!fileCache.has(file.id)) {
			fileCache.set(file.id, (async () => {
				const response = await fetch(`/files/${encodeURIComponent(file.id)}`, { credentials: "same-origin" });
				if (!response.ok) throw new Error(response.status === 404 ? "This file has expired" : "Download failed");
				const key = await crypto.subtle.importKey("raw", fromBase64(file.key), "AES-GCM", false, ["decrypt"]);
				const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(file.iv) }, key, await response.arrayBuffer());
				// Only known images/videos keep their type; everything else is an opaque
				// download so HTML/SVG can never run inside this page.
				const type = SAFE_IMAGES.includes(file.type) || SAFE_VIDEOS.includes(file.type) ? file.type : "application/octet-stream";
				return URL.createObjectURL(new Blob([plain], { type }));
			})());
			fileCache.get(file.id).catch(() => fileCache.delete(file.id));
		}
		return fileCache.get(file.id);
	}

	function saveLink(url, name) {
		const link = el("a", "save-link");
		link.href = url;
		link.download = name;
		link.append(svgIcon("download"), document.createTextNode("Save to device"));
		return link;
	}

	function renderAttachment(file, localUrl) {
		const holder = el("div", "attachment");
		const isImage = SAFE_IMAGES.includes(file.type);
		const isVideo = SAFE_VIDEOS.includes(file.type);

		const showMedia = (url) => {
			holder.replaceChildren();
			if (isImage) {
				const button = el("button", "media");
				button.type = "button";
				const img = el("img");
				img.src = url;
				img.alt = file.name;
				img.addEventListener("load", scrollToEnd, { once: true });
				button.append(img);
				button.addEventListener("click", () => openViewer(url, file.name));
				holder.append(button, saveLink(url, file.name));
			} else if (isVideo) {
				const wrap = el("div", "media");
				const video = el("video");
				video.src = url;
				video.controls = true;
				video.preload = "metadata";
				wrap.append(video);
				holder.append(wrap, saveLink(url, file.name));
			}
		};

		const card = el("div", "file-card");
		const icon = el("span", "file-icon");
		icon.append(svgIcon(isImage || isVideo ? "image" : "file"));
		const info = el("span", "file-info");
		info.append(el("span", "file-name", file.name), el("span", "file-size", formatBytes(file.size)));
		const action = el("button", "file-action");
		action.type = "button";
		action.setAttribute("aria-label", `Download ${file.name}`);
		action.append(svgIcon("download"));
		card.append(icon, info, action);

		if (localUrl && (isImage || isVideo)) {
			showMedia(localUrl);
			return holder;
		}
		holder.append(card);

		const download = async () => {
			action.disabled = true;
			info.lastChild.textContent = "Decrypting…";
			try {
				const url = localUrl || (await decryptFile(file));
				if (isImage || isVideo) return showMedia(url);
				info.lastChild.textContent = formatBytes(file.size);
				const link = el("a");
				link.href = url;
				link.download = file.name;
				document.body.append(link);
				link.click();
				link.remove();
			} catch (error) {
				info.lastChild.textContent = error.message || "Could not decrypt";
			} finally {
				action.disabled = false;
			}
		};
		action.addEventListener("click", download);
		if ((isImage || isVideo) && !localUrl) download(); // previews load automatically
		return holder;
	}

	function openViewer(url, name) {
		$("viewer-image").src = url;
		$("viewer-image").alt = name;
		$("viewer-download").href = url;
		$("viewer-download").download = name;
		$("viewer-dialog").showModal();
	}

	// ---------------- receiving

	async function receive({ from, iv, ct }) {
		const sender = roster.get(from);
		if (!sender?.public_key) return;
		try {
			const plain = await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: fromBase64(iv), additionalData: associatedData(sender.public_key, myKey) },
				await pairKey(sender),
				fromBase64(ct)
			);
			const message = JSON.parse(decoder.decode(plain));
			const id = `${from}:${message.id}`;
			if (typeof message.id !== "string" || seen.has(id)) return; // replayed
			if (typeof message.ts !== "number" || Math.abs(Date.now() - message.ts) > MAX_MESSAGE_AGE_MS) return;
			seen.add(id);
			const text = typeof message.text === "string" ? message.text.slice(0, MAX_MESSAGE_LENGTH) : "";
			const file = validFile(message.file);
			if (!text && !file) return;
			typingUntil.delete(from);
			addMessage({ from, ts: message.ts, text, file, outgoing: false });
			renderPeople();
		} catch {
			addSystem(`A message from ${sender.username} could not be verified and was dropped.`, true);
		}
	}

	function validFile(file) {
		if (!file || typeof file !== "object") return null;
		const ok = ["id", "key", "iv", "name", "type"].every((k) => typeof file[k] === "string") && Number.isFinite(file.size);
		return ok ? { id: file.id, key: file.key, iv: file.iv, name: file.name.slice(0, 120), type: file.type.slice(0, 80), size: file.size } : null;
	}

	// ---------------- sending

	async function encryptFor(plaintext) {
		const envelopes = {};
		for (const person of roster.values()) {
			if (!person.public_key) continue;
			const iv = crypto.getRandomValues(new Uint8Array(12));
			const ciphertext = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv, additionalData: associatedData(myKey, person.public_key) },
				await pairKey(person),
				plaintext
			);
			envelopes[person.id] = { iv: toBase64(iv), ct: toBase64(ciphertext) };
		}
		return envelopes;
	}

	async function deliver(payload) {
		const envelopes = await encryptFor(encoder.encode(JSON.stringify({ ...payload, id: randomToken(12) })));
		if (!Object.keys(envelopes).length) return { ok: false, error: "Nobody else is here yet" };
		return socket.timeout(15000).emitWithAck("send_message", { envelopes }).catch(() => ({ ok: false, error: "Timed out" }));
	}

	function sendText(text) {
		if (!roster.size) {
			toast("Nobody else is here yet. Share the invite link!");
			return false;
		}
		const ts = Date.now();
		const { ticks } = addMessage({ from: me.id, ts, text, outgoing: true });
		outgoing = outgoing.then(async () => setTicks(ticks, await deliver({ text, ts })));
		return true;
	}

	function uploadEncrypted(blob, token, onProgress) {
		return new Promise((resolve, reject) => {
			const xhr = new XMLHttpRequest();
			xhr.open("POST", "/files");
			xhr.setRequestHeader("Content-Type", "application/octet-stream");
			xhr.setRequestHeader("X-Upload-Token", token);
			xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
			xhr.onload = () => (xhr.status === 200 ? resolve(JSON.parse(xhr.responseText)) : reject(new Error(xhr.status === 413 ? "File too large" : "Upload failed")));
			xhr.onerror = () => reject(new Error("Upload failed"));
			xhr.send(blob);
		});
	}

	function sendFile(file) {
		if (!roster.size) {
			toast("Nobody else is here yet. Share the invite link!");
			return;
		}
		if (file.size > maxFileBytes) {
			toast(`${file.name} is larger than ${formatBytes(maxFileBytes)}.`, "error");
			return;
		}
		const ts = Date.now();
		const type = (file.type || "application/octet-stream").slice(0, 80);
		const localUrl = URL.createObjectURL(file);
		const meta = { id: "", key: "", iv: "", name: (file.name || "photo.jpg").slice(0, 120), type, size: file.size };
		const { bubble, ticks } = addMessage({ from: me.id, ts, file: meta, outgoing: true, localUrl });
		const bar = el("div", "progress");
		const fill = el("span");
		bar.append(fill);
		bubble.insertBefore(bar, bubble.lastChild);

		outgoing = outgoing.then(async () => {
			try {
				const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
				const iv = crypto.getRandomValues(new Uint8Array(12));
				const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, await file.arrayBuffer());
				const grant = await socket.timeout(10000).emitWithAck("file_upload_token");
				if (!grant?.ok) throw new Error(grant?.error || "Upload refused");
				const { id } = await uploadEncrypted(new Blob([ciphertext]), grant.token, (p) => (fill.style.width = `${Math.round(p * 100)}%`));
				const rawKey = toBase64(await crypto.subtle.exportKey("raw", key));
				const result = await deliver({ ts, file: { ...meta, id, key: rawKey, iv: toBase64(iv) } });
				bar.remove();
				setTicks(ticks, result);
				if (!localUrl || !(SAFE_IMAGES.includes(type) || SAFE_VIDEOS.includes(type))) {
					// let the sender save their own non-media files too
					bubble.querySelector(".file-action")?.addEventListener("click", () => {
						const a = el("a");
						a.href = localUrl;
						a.download = meta.name;
						a.click();
					}, { once: true });
				}
			} catch (error) {
				bar.remove();
				setTicks(ticks, { ok: false, error: error.message });
				toast(error.message || "Could not send file", "error");
			}
		});
	}

	// ---------------- verification

	let verifyTarget = null;

	async function openVerify(id) {
		const person = roster.get(id);
		if (!person?.public_key) return;
		verifyTarget = id;
		const digest = await fingerprint(myKey, person.public_key);
		$("verify-avatar").replaceWith(Object.assign(avatar(person, "lg", person.online), { id: "verify-avatar" }));
		$("verify-title").textContent = person.username;
		document.querySelectorAll(".verify-name").forEach((n) => (n.textContent = person.username));
		const state = trustState(person);
		const chip = $("verify-status");
		chip.className = `trust-chip ${state}`;
		chip.replaceChildren(
			svgIcon(state === "verified" ? "shield-check" : state === "changed" ? "warn" : "shield"),
			document.createTextNode(state === "verified" ? "Verified" : state === "changed" ? "Safety number changed" : "Not verified yet")
		);
		$("verify-emoji").replaceChildren(
			...emojiCode(digest).map(([emoji, name]) => {
				const cell = el("div", "emoji-cell");
				cell.append(el("span", "e", emoji), el("span", "n", name));
				return cell;
			})
		);
		$("verify-numbers").textContent = numberCode(digest);
		$("verify-match").textContent = state === "verified" ? "Remove verification" : "They match";
		$("verify-match").className = state === "verified" ? "btn ghost" : "btn";
		$("verify-mismatch").hidden = state === "verified";
		$("verify-note").textContent = state === "changed"
			? `${person.username} has a new key. They may have cleared their browser or used a new device, or someone may be intercepting. Compare again.`
			: "";
		const dialog = $("verify-dialog");
		if (!dialog.open) dialog.showModal();
	}

	$("verify-match").addEventListener("click", () => {
		const person = roster.get(verifyTarget);
		if (!person) return;
		if (trustState(person) === "verified") {
			delete verified[person.public_key];
			toast(`${person.username} is no longer marked as verified.`);
		} else {
			verified[person.public_key] = true;
			pins[person.username] = person.public_key;
			savePins();
			toast(`✓ ${person.username} is verified. Your chat is private.`);
		}
		saveVerified();
		renderPeople();
		openVerify(person.id);
	});

	$("verify-mismatch").addEventListener("click", () => {
		$("verify-note").textContent =
			"Don't share anything sensitive. Ask them to reload the page and compare again. If it still differs, someone may be intercepting.";
	});

	// ---------------- profile

	$("me-card").addEventListener("click", () => {
		if (!me) return;
		$("profile-avatar").replaceWith(Object.assign(avatar(me, "lg"), { id: "profile-avatar" }));
		$("profile-name").value = me.username;
		document.querySelectorAll('input[name="profile-gender"]').forEach((r) => (r.checked = r.value === me.gender));
		$("profile-error").textContent = "";
		$("profile-dialog").showModal();
	});

	$("profile-form").addEventListener("submit", async (event) => {
		event.preventDefault();
		const username = $("profile-name").value.trim();
		const gender = document.querySelector('input[name="profile-gender"]:checked')?.value || me.gender;
		const result = await socket.timeout(10000).emitWithAck("update_profile", { username, gender }).catch(() => null);
		if (!result?.ok) {
			$("profile-error").textContent = result?.error || "Could not save. Try again.";
			return;
		}
		me = result.me;
		profile = { username: me.username, gender: me.gender };
		store.set("profile", profile);
		renderMe();
		$("profile-dialog").close();
		toast("Profile saved");
	});

	// ---------------- composer

	function autoGrow() {
		ui.input.style.height = "auto";
		ui.input.style.height = `${Math.min(ui.input.scrollHeight, 160)}px`;
	}

	let lastTypingSent = 0;
	ui.input.addEventListener("input", () => {
		autoGrow();
		ui.send.disabled = !ui.input.value.trim() || !socket?.connected;
		if (ui.input.value && Date.now() - lastTypingSent > 2500 && socket?.connected) {
			lastTypingSent = Date.now();
			socket.emit("typing");
		}
	});

	ui.input.addEventListener("keydown", (event) => {
		if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
			event.preventDefault();
			$("composer").requestSubmit();
		}
	});

	$("composer").addEventListener("submit", (event) => {
		event.preventDefault();
		const text = ui.input.value.trim().slice(0, MAX_MESSAGE_LENGTH);
		if (!text || !socket?.connected) return;
		if (sendText(text)) {
			ui.input.value = "";
			autoGrow();
			ui.send.disabled = true;
		}
	});

	ui.input.addEventListener("paste", (event) => {
		const files = [...(event.clipboardData?.files || [])];
		if (files.length) {
			event.preventDefault();
			files.forEach(sendFile);
		}
	});

	// attach menu
	const closeMenu = () => {
		ui.attachMenu.hidden = true;
		ui.attach.setAttribute("aria-expanded", "false");
	};
	ui.attach.addEventListener("click", (event) => {
		event.stopPropagation();
		ui.attachMenu.hidden = !ui.attachMenu.hidden;
		ui.attach.setAttribute("aria-expanded", String(!ui.attachMenu.hidden));
	});
	document.addEventListener("click", (event) => {
		if (!ui.attachMenu.contains(event.target)) closeMenu();
	});
	ui.attachMenu.addEventListener("click", (event) => {
		const action = event.target.closest("[data-action]")?.dataset.action;
		closeMenu();
		if (action === "camera") openCamera();
		if (action === "media") $("media-input").click();
		if (action === "file") $("file-input").click();
	});
	for (const id of ["media-input", "file-input", "camera-input"]) {
		$(id).addEventListener("change", (event) => {
			[...event.target.files].forEach(sendFile);
			event.target.value = "";
		});
	}

	// drag & drop
	let dragDepth = 0;
	const chat = $("chat");
	chat.addEventListener("dragenter", (e) => {
		if (![...(e.dataTransfer?.types || [])].includes("Files") || !socket?.connected) return;
		dragDepth++;
		$("drop-overlay").hidden = false;
	});
	chat.addEventListener("dragleave", () => {
		if (--dragDepth <= 0) {
			dragDepth = 0;
			$("drop-overlay").hidden = true;
		}
	});
	chat.addEventListener("dragover", (e) => e.preventDefault());
	chat.addEventListener("drop", (e) => {
		e.preventDefault();
		dragDepth = 0;
		$("drop-overlay").hidden = true;
		[...(e.dataTransfer?.files || [])].forEach(sendFile);
	});

	// ---------------- camera

	let stream = null;
	let facing = "environment";
	let capturedBlob = null;

	async function openCamera() {
		if (!navigator.mediaDevices?.getUserMedia) {
			$("camera-input").click(); // mobile fallback opens the native camera
			return;
		}
		$("camera-dialog").showModal();
		showCameraLive();
		await startStream();
	}

	async function startStream() {
		stopStream();
		try {
			stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: facing }, audio: false });
			$("camera-video").srcObject = stream;
			await $("camera-video").play();
		} catch {
			$("camera-dialog").close();
			toast("Camera not available. Choose a photo instead.", "error");
			$("camera-input").click();
		}
	}

	function stopStream() {
		stream?.getTracks().forEach((t) => t.stop());
		stream = null;
	}

	function showCameraLive() {
		capturedBlob = null;
		$("camera-video").hidden = false;
		$("camera-preview").hidden = true;
		$("camera-shutter").hidden = false;
		$("camera-flip").hidden = false;
		$("camera-retake").hidden = true;
		$("camera-send").hidden = true;
	}

	$("camera-shutter").addEventListener("click", () => {
		const video = $("camera-video");
		if (!video.videoWidth) return;
		const canvas = document.createElement("canvas");
		canvas.width = video.videoWidth;
		canvas.height = video.videoHeight;
		canvas.getContext("2d").drawImage(video, 0, 0);
		canvas.toBlob((blob) => {
			capturedBlob = blob;
			$("camera-preview").src = URL.createObjectURL(blob);
			$("camera-video").hidden = true;
			$("camera-preview").hidden = false;
			$("camera-shutter").hidden = true;
			$("camera-flip").hidden = true;
			$("camera-retake").hidden = false;
			$("camera-send").hidden = false;
		}, "image/jpeg", 0.9);
	});
	$("camera-retake").addEventListener("click", showCameraLive);
	$("camera-flip").addEventListener("click", () => {
		facing = facing === "environment" ? "user" : "environment";
		startStream();
	});
	$("camera-send").addEventListener("click", () => {
		if (capturedBlob) {
			const name = `photo-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)}.jpg`;
			sendFile(new File([capturedBlob], name, { type: "image/jpeg" }));
		}
		$("camera-dialog").close();
	});
	$("camera-dialog").addEventListener("close", stopStream);

	// ---------------- misc chrome

	$("open-sidebar").addEventListener("click", () => ui.app.classList.add("drawer-open"));
	$("close-sidebar").addEventListener("click", () => ui.app.classList.remove("drawer-open"));
	$("scrim").addEventListener("click", () => ui.app.classList.remove("drawer-open"));
	ui.stack.addEventListener("click", () => ui.app.classList.add("drawer-open"));
	$("info-button").addEventListener("click", () => $("info-dialog").showModal());
	$("copy-link").addEventListener("click", async () => {
		try {
			await navigator.clipboard.writeText(location.origin + location.pathname);
			toast("Invite link copied");
		} catch {
			toast(location.origin);
		}
	});
	setInterval(renderPeople, 15000); // refresh "last seen" labels

	// ---------------- socket

	function setOnline(online) {
		ui.pill.classList.toggle("offline", !online);
		ui.pill.lastChild.textContent = online ? "Encrypted" : "Offline";
		ui.input.disabled = !online;
		ui.attach.disabled = !online;
		ui.send.disabled = !online || !ui.input.value.trim();
	}

	function upsert(person) {
		const previous = roster.get(person.id);
		if (previous && previous.public_key !== person.public_key) pairKeys.delete(previous.public_key);
		roster.set(person.id, { ...previous, ...person });
		checkPin(person);
	}

	function connect() {
		if (socket) return;
		socket = io({
			transports: ["websocket"],
			// A function, so reconnects always send the current name.
			auth: (cb) => cb({ public_key: myKey, token, username: profile.username, gender: profile.gender, returning }),
		});

		socket.on("connect", () => setOnline(true));
		socket.on("disconnect", () => {
			setOnline(false);
			renderPeople();
		});
		socket.on("connect_error", (error) => {
			setOnline(false);
			if (error.message === "name_taken" || error.message === "bad_name") {
				socket.disconnect();
				socket = null;
				askProfile(error.message === "name_taken" ? "That name is already in use. Pick another one." : "Use 2–24 letters, digits, spaces, _ or -.");
			} else {
				ui.roomSub.textContent = "Can't reach the server. Retrying…";
			}
		});

		socket.on("welcome", (data) => {
			returning = true;
			me = data.me;
			maxFileBytes = data.max_file_bytes || maxFileBytes;
			profile = { username: me.username, gender: me.gender };
			store.set("profile", profile);
			roster.clear();
			data.members.forEach(upsert);
			renderMe();
			renderPeople();
			setOnline(true);
			if (window.matchMedia("(min-width: 821px)").matches) ui.input.focus();
		});

		socket.on("user_joined", (person) => {
			upsert(person);
			addSystem(`${person.username} joined`);
			renderPeople();
		});

		socket.on("presence", (person) => {
			upsert(person);
			if (!person.online) typingUntil.delete(person.id);
			renderPeople();
		});

		socket.on("profile_updated", (data) => {
			if (me && data.id === me.id) return;
			const previous = roster.get(data.id);
			if (previous && data.old_username !== data.username) {
				// Move the key pin to the new name so it isn't mistaken for a key change.
				if (pins[data.old_username] === data.public_key) {
					pins[data.username] = data.public_key;
					delete pins[data.old_username];
					savePins();
				}
				addSystem(`${data.old_username} is now ${data.username}`);
			}
			upsert(data);
			renderPeople();
		});

		socket.on("typing", ({ id }) => {
			typingUntil.set(id, Date.now() + 3500);
			renderPeople();
			setTimeout(renderPeople, 3600);
		});

		socket.on("new_message", (data) => {
			incoming = incoming.then(() => receive(data));
		});
	}

	if (profile) connect();
	else askProfile();
}

// ------------------------------------------------------------------ theme & dialogs

function setupTheme() {
	const root = document.documentElement;
	const saved = store.get("theme");
	if (saved) root.dataset.theme = saved;
	const isDark = () => (root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches);
	const paint = () => $("theme-toggle").replaceChildren(svgIcon(isDark() ? "sun" : "moon"));
	paint();
	$("theme-toggle").addEventListener("click", () => {
		root.dataset.theme = isDark() ? "light" : "dark";
		store.set("theme", root.dataset.theme);
		paint();
	});
}

function setupDialogs() {
	for (const dialog of document.querySelectorAll("dialog")) {
		dialog.addEventListener("click", (event) => {
			if (event.target.closest("[data-close]")) return dialog.close();
			if (event.target !== dialog) return;
			// Only a click on the backdrop (outside the dialog box) closes it.
			const r = dialog.getBoundingClientRect();
			const inside = event.clientX >= r.left && event.clientX <= r.right && event.clientY >= r.top && event.clientY <= r.bottom;
			if (!inside) dialog.close();
		});
	}
}

main();
