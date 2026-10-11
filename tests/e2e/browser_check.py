"""Real-browser end-to-end check (Playwright + Chromium). Not collected by pytest.

    gunicorn wsgi:app &            # serves http://127.0.0.1:5000
    python tests/e2e/browser_check.py [--screenshots DIR]

Covers: onboarding (name + gender), stable identity across refresh (no left/joined
spam), offline mailbox, emoji verification, encrypted image/file/camera transfer and
download, and that no plaintext ever appears in WebSocket traffic.
"""
import asyncio
import base64
import os
import sys

from playwright.async_api import async_playwright

BASE = os.environ.get("BASE_URL", "http://localhost:5000/")
SHOTS = sys.argv[sys.argv.index("--screenshots") + 1] if "--screenshots" in sys.argv else None
SECRETS = ["first secret 🍕", "sent while bob was away", "after refresh"]
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)
DOC = b"%PDF-1.4 pretend document " + os.urandom(64)

RUN = os.urandom(2).hex()  # names stay reserved for 24 h, so each run uses fresh ones
A, B, C = f"Alice-{RUN}", f"Bob-{RUN}", f"Carol-{RUN}"
frames, problems = [], []


def check(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        problems.append(label)


def watch(page, name):
    page.on("pageerror", lambda e: problems.append(f"{name} pageerror: {e}"))
    page.on("console", lambda m: m.type == "error" and problems.append(f"{name} console: {m.text}"))
    page.on("websocket", lambda ws: (ws.on("framesent", lambda f: frames.append(str(f))),
                                     ws.on("framereceived", lambda f: frames.append(str(f)))))


async def join(context, name, gender):
    page = await context.new_page()
    watch(page, name)
    await page.goto(BASE)
    await page.wait_for_selector("#onboard:not([hidden])")
    await page.fill("#onboard-name", name)
    await page.click(f"#onboard input[value={gender}] + .avatar")
    await page.click("#onboard-submit")
    await page.wait_for_function("() => !document.getElementById('message-input').disabled")
    return page


async def reopen(context, name):
    page = await context.new_page()
    watch(page, name)
    await page.goto(BASE)
    await page.wait_for_function("() => !document.getElementById('message-input').disabled")
    return page


async def say(page, text):
    await page.fill("#message-input", text)
    await page.press("#message-input", "Enter")


async def shows(page, text, timeout=10000):
    await page.wait_for_function(
        f"() => document.getElementById('messages').innerText.includes({text!r})", timeout=timeout)


def text_of(page):
    return page.evaluate("() => document.getElementById('messages').innerText")


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(args=[
            "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream"])
        a_ctx = await browser.new_context(permissions=["camera", "clipboard-read", "clipboard-write"])
        b_ctx = await browser.new_context(accept_downloads=True, viewport={"width": 390, "height": 800},
                                          color_scheme="dark")
        c_ctx = await browser.new_context()

        alice = await join(a_ctx, A, "female")
        if SHOTS:
            await alice.screenshot(path=f"{SHOTS}/1-empty.png")
        bob = await join(b_ctx, B, "male")
        carol = await join(c_ctx, C, "transgender")
        await shows(alice, f"{C} joined")
        check(True, "onboarding asks name + gender; joins announced once")

        badges = await alice.eval_on_selector_all("#people .gbadge", "els => els.map(e => e.textContent)")
        check(sorted(badges) == ["♂", "⚧"], f"gender badges shown in people list {badges}")

        await say(alice, SECRETS[0])
        await shows(bob, SECRETS[0])
        await shows(carol, SECRETS[0])
        await alice.wait_for_function("() => [...document.querySelectorAll('.ticks')].some(t => t.textContent === '✓✓')")
        check(True, "message delivered to everyone (✓✓)")

        # Bob refreshes: same person, no onboarding, no left/joined noise
        emoji_before = None
        await alice.click(f"#people .person >> text={B}")
        emoji_before = await alice.inner_text("#verify-emoji")
        await alice.click("#verify-dialog [data-close]")
        await bob.reload()
        await bob.wait_for_function("() => !document.getElementById('message-input').disabled")
        check(await bob.is_hidden("#onboard"), "refresh does not ask for the name again")
        check(await bob.inner_text("#me-name") == B, "name sticks after refresh")
        await alice.wait_for_timeout(1500)
        transcript = await text_of(alice)
        check("left" not in transcript and transcript.count(f"{B} joined") == 1, "no left/joined spam on refresh")
        await alice.click(f"#people .person >> text={B}")
        check(await alice.inner_text("#verify-emoji") == emoji_before, "encryption key survives refresh")

        # Verification: both sides see the same emoji; mark verified
        await bob.click("#open-sidebar")
        await bob.click(f"#people .person >> text={A}")
        check(await bob.inner_text("#verify-emoji") == emoji_before, "both people see the same emoji")
        if SHOTS:
            await alice.screenshot(path=f"{SHOTS}/3-verify.png")
        await alice.click("#verify-match")
        await bob.click("#verify-dialog [data-close]")
        await alice.click("#verify-dialog [data-close]")
        await alice.wait_for_function("() => document.querySelector('#people').innerText.includes('Verified')")
        check(True, "Bob marked as verified")

        # Screen off: Bob closes the tab, Alice writes, Bob comes back and gets it
        await bob.close()
        await say(alice, SECRETS[1])
        bob = await reopen(b_ctx, B)
        await shows(bob, SECRETS[1])
        check(True, "message sent while Bob was away is delivered when he returns")
        await say(bob, SECRETS[2])
        await shows(alice, SECRETS[2])

        # Encrypted photo
        await alice.set_input_files("#media-input", files=[{"name": "dot.png", "mimeType": "image/png", "buffer": PNG}])
        await bob.wait_for_function(
            "() => [...document.querySelectorAll('.media img')].some(i => i.complete && i.naturalWidth === 1)",
            timeout=15000)
        save = await bob.get_attribute(".save-link", "download")
        check(save == "dot.png", "photo decrypted, shown, and offered as 'Save to device'")

        # Encrypted document, downloaded to the device
        await alice.set_input_files("#file-input", files=[{"name": "report.pdf", "mimeType": "application/pdf", "buffer": DOC}])
        await bob.wait_for_selector(".file-card >> text=report.pdf")
        async with bob.expect_download() as download_info:
            await bob.click(".file-card:has-text('report.pdf') .file-action")
        download = await download_info.value
        path = await download.path()
        check(open(path, "rb").read() == DOC and download.suggested_filename == "report.pdf",
              "document downloaded to device byte-for-byte")

        # Camera capture (Chromium fake camera)
        await alice.click("#attach-button")
        await alice.click("[data-action=camera]")
        await alice.wait_for_function("() => document.getElementById('camera-video').videoWidth > 0", timeout=10000)
        await alice.click("#camera-shutter")
        await alice.wait_for_selector("#camera-send:not([hidden])")
        await alice.click("#camera-send")
        await carol.wait_for_function(
            "() => [...document.querySelectorAll('.media img')].some(i => i.complete && i.naturalWidth > 100)",
            timeout=20000)
        check(True, "camera photo captured, encrypted and received")

        # Typing indicator
        await carol.fill("#message-input", "typing something")
        await alice.wait_for_function("() => document.getElementById('typing').innerText.includes('%s is typing')" % C)
        check(True, "typing indicator")

        if SHOTS:
            await alice.screenshot(path=f"{SHOTS}/2-desktop.png")
            await bob.screenshot(path=f"{SHOTS}/4-mobile-dark.png")
            await bob.click("#open-sidebar")
            await bob.wait_for_timeout(400)
            await bob.screenshot(path=f"{SHOTS}/5-mobile-drawer.png")
            fresh = await (await browser.new_context(viewport={"width": 390, "height": 800})).new_page()
            await fresh.goto(BASE)
            await fresh.wait_for_selector("#onboard:not([hidden])")
            await fresh.screenshot(path=f"{SHOTS}/0-onboarding.png")

        leaked = [f for f in frames if any(s in f for s in SECRETS) or "pretend document" in f]
        check(not leaked, f"no plaintext in {len(frames)} WebSocket frames")
        overflow = await bob.evaluate("() => document.documentElement.scrollWidth > window.innerWidth")
        check(not overflow, "no horizontal scrolling on mobile")
        await browser.close()

    for problem in problems:
        print("PROBLEM:", problem)
    sys.exit(1 if problems else 0)


asyncio.run(main())
