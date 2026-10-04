<div align="center">

# 💬 Real-Time Chat App

**A live group chat built with Flask and Socket.IO. Open it in two browser tabs and messages appear instantly.**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![Socket.IO](https://img.shields.io/badge/Socket.IO-010101?style=flat-square&logo=socketdotio&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![Gunicorn](https://img.shields.io/badge/Gunicorn-eventlet-499848?style=flat-square&logo=gunicorn&logoColor=white)

</div>

---

## ✨ Features

- ⚡ **Real-time messaging** over WebSockets, with no page refreshes
- 🎲 **Instant identity**: every visitor gets a random username (`User_1234`) and avatar
- ✏️ **Change your username**; everyone sees the update live
- 👋 **Join / leave notifications** when users connect or disconnect
- 🚀 **Deployment-ready** with `wsgi.py`, Gunicorn and eventlet

---

## 🔌 Socket events

| Direction | Event | Payload |
|---|---|---|
| Server → client | `set_username` | Your assigned username |
| Server → all | `user_joined` / `user_left` | Username (+ avatar) |
| Client → server | `send_message` | `{ message }` |
| Server → all | `new_message` | `{ username, avatar, message }` |
| Client → server | `update_username` | `{ username }` |
| Server → all | `username_updated` | `{ old_username, new_username }` |

---

## 🚀 Run locally

```bash
git clone https://github.com/gmgowrish/chat_application.git
cd chat_application

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python app.py
```

Open **http://127.0.0.1:5000/** in two browser tabs and start chatting.

### Production

```bash
gunicorn --worker-class eventlet -w 1 wsgi:app
```

---

## 📁 Project Structure

```
chat_application/
├── app.py              # Flask app + Socket.IO event handlers
├── wsgi.py             # entry point for Gunicorn
├── templates/
│   └── index.html      # chat UI + Socket.IO client
└── requirements.txt
```

## 🛠️ Tech Stack

**Python** · **Flask** · **Flask-SocketIO** · **Socket.IO (JS client)** · **Gunicorn + eventlet** · avatars from [avatar.iran.liara.run](https://avatar.iran.liara.run)

> Users are kept in memory and messages aren't stored, so the user list resets when the server restarts.

---

<div align="center">

Made by **[G M Gowrish](https://github.com/gmgowrish)** · ⭐ Star the repo if you find it useful!

</div>
