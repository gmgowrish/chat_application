// End-to-end encrypted chat client.
//
// Crypto design (all done in the browser with the Web Crypto API):
//   * Each tab creates an ECDH P-256 key pair. The private key is non-extractable
//     and never leaves the browser; only the public key is sent to the server.
//   * For every other member we derive a pairwise AES-256-GCM key:
//     ECDH shared secret -> HKDF-SHA-256 (bound to both public keys).
//   * A message is encrypted separately for each recipient with a fresh random IV.
//     The AAD binds sender and recipient keys, so the server cannot reflect or
//     re-route a ciphertext, and a per-sender sequence number blocks replays.
//   * Safety numbers (SHA-512 of both public keys) let two people confirm out of
//     band that the server did not swap in its own keys (man-in-the-middle).

const PROTOCOL = "e2ee-chat-v1";
const MAX_MESSAGE_LENGTH = 2000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64(buffer) {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
	return btoa(binary);
}

function fromBase64(text) {
	return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function associatedData(senderKey, recipientKey) {
	return encoder.encode(`${PROTOCOL}|from:${senderKey}|to:${recipientKey}`);
}

async function derivePairKey(privateKey, myPublicKey, peerPublicKey) {
	const peer = await crypto.subtle.importKey(
		"raw",
		fromBase64(peerPublicKey),
		{ name: "ECDH", namedCurve: "P-256" },
		false,
		[]
	);
	const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256);
	const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
	const [a, b] = [myPublicKey, peerPublicKey].sort();
	return crypto.subtle.deriveKey(
		{ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: encoder.encode(`${PROTOCOL}|${a}|${b}`) },
		hkdfKey,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"]
	);
}

async function safetyNumber(keyA, keyB) {
	const [first, second] = [keyA, keyB].sort();
	const digest = new Uint8Array(
		await crypto.subtle.digest("SHA-512", new Uint8Array([...fromBase64(first), ...fromBase64(second)]))
	);
	const view = new DataView(digest.buffer);
	const groups = [];
	for (let i = 0; i < 12; i++) groups.push(String(view.getUint32(i * 4) % 100000).padStart(5, "0"));
	return [0, 4, 8].map((i) => groups.slice(i, i + 4).join(" ")).join("\n");
}

function avatarFor(name, seed) {
	const avatar = document.createElement("div");
	avatar.className = "avatar";
	avatar.textContent = (name.trim()[0] || "?").toUpperCase();
	let hash = 0;
	for (const ch of seed) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
	avatar.style.backgroundColor = `hsl(${hash % 360}, 55%, 50%)`;
	return avatar;
}

async function main() {
	const chatMessages = document.getElementById("chat-messages");
	const messageInput = document.getElementById("message-input");
	const sendButton = document.getElementById("send-button");
	const currentUsernameSpan = document.getElementById("current-username");
	const usernameInput = document.getElementById("username-input");
	const updateUsernameButton = document.getElementById("update-username-button");
	const memberList = document.getElementById("member-list");
	const e2eeStatus = document.getElementById("e2ee-status");
	const verifyDialog = document.getElementById("verify-dialog");

	if (!window.crypto || !crypto.subtle) {
		e2eeStatus.textContent = "⚠ Encryption needs HTTPS (or localhost). Chat disabled.";
		return;
	}

	const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
		"deriveBits",
	]);
	const myPublicKey = toBase64(await crypto.subtle.exportKey("raw", keyPair.publicKey));

	let myId = "";
	let myUsername = "";
	let mySequence = 0;
	// id -> { username, publicKey, key: Promise<CryptoKey>, lastSequence }
	const members = new Map();
	// Decrypt one message at a time so sequence numbers are checked in arrival order.
	let incoming = Promise.resolve();
	let outgoing = Promise.resolve();

	const socket = io({ auth: { public_key: myPublicKey }, transports: ["websocket"] });

	function addMember(member) {
		members.set(member.id, {
			username: member.username,
			publicKey: member.public_key,
			key: derivePairKey(keyPair.privateKey, myPublicKey, member.public_key),
			lastSequence: 0,
		});
		renderMembers();
	}

	function renderMembers() {
		memberList.replaceChildren();
		for (const [id, member] of members) {
			const item = document.createElement("li");
			const button = document.createElement("button");
			button.title = `Verify encryption with ${member.username}`;
			const label = document.createElement("span");
			label.textContent = member.username;
			button.append(avatarFor(member.username, id), label);
			button.addEventListener("click", () => showSafetyNumber(member));
			item.appendChild(button);
			memberList.appendChild(item);
		}
	}

	async function showSafetyNumber(member) {
		document.getElementById("verify-name").textContent = member.username;
		document.getElementById("verify-name-2").textContent = member.username;
		document.getElementById("safety-number").textContent = await safetyNumber(myPublicKey, member.publicKey);
		verifyDialog.showModal();
	}

	function setMyUsername(name) {
		myUsername = name;
		currentUsernameSpan.textContent = `Your username: ${name}`;
	}

	socket.on("welcome", (data) => {
		myId = data.id;
		setMyUsername(data.username);
		members.clear();
		data.members.forEach(addMember);
		renderMembers();
		e2eeStatus.textContent = "🔒 End-to-end encrypted · the server only sees ciphertext";
		messageInput.disabled = false;
		sendButton.disabled = false;
		messageInput.focus();
	});

	socket.on("connect_error", () => {
		e2eeStatus.textContent = "⚠ Not connected. Retrying…";
	});

	socket.on("disconnect", () => {
		// On reconnect the server sends a fresh "welcome" with a new id and member list.
		e2eeStatus.textContent = "⚠ Disconnected. Reconnecting…";
		messageInput.disabled = true;
		sendButton.disabled = true;
	});

	socket.on("user_joined", (data) => {
		addMember(data);
		addSystemMessage(`${data.username} joined the chat`);
	});

	socket.on("user_left", (data) => {
		const member = members.get(data.id);
		if (!member) return;
		members.delete(data.id);
		renderMembers();
		addSystemMessage(`${member.username} left the chat`);
	});

	socket.on("username_updated", (data) => {
		if (data.id === myId) {
			addSystemMessage(`You are now ${data.username}`);
			setMyUsername(data.username);
			return;
		}
		const member = members.get(data.id);
		if (!member) return;
		addSystemMessage(`${member.username} changed their name to ${data.username}`);
		member.username = data.username;
		renderMembers();
	});

	socket.on("error_message", (data) => addSystemMessage(data.error, true));

	socket.on("new_message", (data) => {
		incoming = incoming.then(() => receive(data));
	});

	async function receive({ from, iv, ct }) {
		const member = members.get(from);
		if (!member) return;
		try {
			const plaintext = await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: fromBase64(iv), additionalData: associatedData(member.publicKey, myPublicKey) },
				await member.key,
				fromBase64(ct)
			);
			const { text, seq } = JSON.parse(decoder.decode(plaintext));
			if (typeof text !== "string" || !Number.isInteger(seq) || seq <= member.lastSequence) {
				throw new Error("replayed or malformed message");
			}
			member.lastSequence = seq;
			addUserMessage(text, member.username, from, false);
		} catch {
			addSystemMessage(`⚠ A message from ${member.username} failed verification and was dropped.`, true);
		}
	}

	function sendMessage() {
		const text = messageInput.value.trim().slice(0, MAX_MESSAGE_LENGTH);
		if (!text || messageInput.disabled) return;
		if (members.size === 0) {
			addSystemMessage("Nobody else is here yet, so there is no one to encrypt for.", true);
			return;
		}
		messageInput.value = "";
		// Encrypt and emit one message at a time so recipients see increasing sequence numbers.
		outgoing = outgoing.then(() => encryptAndSend(text)).catch(() => {
			addSystemMessage("⚠ Could not encrypt that message.", true);
		});
	}

	async function encryptAndSend(text) {
		const plaintext = encoder.encode(JSON.stringify({ text, seq: ++mySequence }));
		const envelopes = {};
		for (const [id, member] of members) {
			const iv = crypto.getRandomValues(new Uint8Array(12));
			const ciphertext = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv, additionalData: associatedData(myPublicKey, member.publicKey) },
				await member.key,
				plaintext
			);
			envelopes[id] = { iv: toBase64(iv), ct: toBase64(ciphertext) };
		}
		socket.emit("send_message", { envelopes });
		addUserMessage(text, myUsername, myId, true);
	}

	function updateUsername() {
		const newUsername = usernameInput.value.trim();
		if (newUsername && newUsername !== myUsername) {
			socket.emit("update_username", { username: newUsername });
			usernameInput.value = "";
		}
	}

	function addUserMessage(text, username, senderId, isSent) {
		const messageElement = document.createElement("div");
		messageElement.className = isSent ? "message sent" : "message";

		const contentDiv = document.createElement("div");
		contentDiv.className = "message-content";
		const usernameDiv = document.createElement("div");
		usernameDiv.className = "message-username";
		usernameDiv.textContent = username;
		const messageText = document.createElement("div");
		messageText.textContent = text; // textContent, never innerHTML: no XSS from message text
		contentDiv.append(usernameDiv, messageText);

		messageElement.append(avatarFor(username, senderId), contentDiv);
		appendToChat(messageElement);
	}

	function addSystemMessage(text, isWarning = false) {
		const messageElement = document.createElement("div");
		messageElement.className = isWarning ? "system-message warning" : "system-message";
		messageElement.textContent = text;
		appendToChat(messageElement);
	}

	function appendToChat(element) {
		chatMessages.appendChild(element);
		chatMessages.scrollTop = chatMessages.scrollHeight;
	}

	sendButton.addEventListener("click", sendMessage);
	messageInput.addEventListener("keydown", (e) => {
		if (e.key === "Enter") sendMessage();
	});
	updateUsernameButton.addEventListener("click", updateUsername);
	document.getElementById("verify-close").addEventListener("click", () => verifyDialog.close());
}

main();
