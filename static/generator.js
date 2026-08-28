document.addEventListener("DOMContentLoaded", () => {
    // Sent with every state-changing request; the server compares it
    // against the copy in the signed session cookie.
    const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

    function jsonHeaders() {
        return {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken
        };
    }

    const generateBtn = document.getElementById("generate");
    const copyBtn = document.getElementById("copy-clipboard");
    const saveBtn = document.getElementById("save-to-DB");
    const output = document.getElementById("output");
    const lengthInput = document.getElementById("length");
    const siteInput = document.getElementById("site");
    const usernameInput = document.getElementById("username");
    const message = document.getElementById("generator-message");

    let messageTimeout;

    const CLIPBOARD_CLEAR_MS = 30000;
    let clipboardTimer;

    // A copied password otherwise sits on the clipboard indefinitely, readable
    // by anything that asks for it.
    function clearClipboardLater(copied) {
        clearTimeout(clipboardTimer);

        clipboardTimer = setTimeout(async () => {
            try {
                // Only wipe it if it is still ours - something else may have
                // been copied in the meantime.
                if (await navigator.clipboard.readText() !== copied) {
                    return;
                }
            } catch (denied) {
                // Reading needs a permission we may not have. Clearing is the
                // safer default, so fall through.
            }

            try {
                await navigator.clipboard.writeText("");
            } catch (needsFocus) {
                // Writing requires the document to be focused; nothing to do.
            }
        }, CLIPBOARD_CLEAR_MS);
    }


    // Replaces both the absolutely-positioned divs that used to float over the
    // rest of the page, and alert(), which embedded browsers suppress outright
    // so a missing field produced no feedback at all.
    function showMessage(text, kind) {
        clearTimeout(messageTimeout);

        message.textContent = text;
        message.dataset.kind = kind;

        // Successes clear themselves; problems stay until the next action, so
        // there is time to read which field is missing.
        if (kind === "ok") {
            messageTimeout = setTimeout(() => {
                message.textContent = "";
            }, 2500);
        }
    }

    // "site", "site and username", "site, username and password"
    function listFields(items) {
        if (items.length < 2) {
            return items.join("");
        }

        return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
    }

    function clearMessage() {
        clearTimeout(messageTimeout);
        message.textContent = "";
    }

    generateBtn.addEventListener("click", async () => {
        const response = await fetch(`/generate?length=${lengthInput.value || 16}`);

        if (!response.ok) {
            showMessage("Could not generate a password", "error");
            return;
        }

        output.value = await response.text();
        clearMessage();
    });

    copyBtn.addEventListener("click", async () => {
        if (!output.value.trim()) {
            showMessage("Nothing to copy - generate a password first", "error");
            return;
        }

        const copied = output.value;

        // Writing needs the document focused and the API can be blocked
        // outright; without this the button would fail silently.
        try {
            await navigator.clipboard.writeText(copied);
        } catch (refused) {
            showMessage("Could not reach the clipboard - copy it by hand", "error");
            return;
        }

        clearClipboardLater(copied);

        showMessage("Copied - the clipboard clears in 30 seconds", "ok");
    });

    saveBtn.addEventListener("click", async () => {
        const site = siteInput.value.trim();
        const username = usernameInput.value.trim();
        const password = output.value.trim();

        const missing = [];

        if (!site) {
            missing.push("site");
        }

        if (!username) {
            missing.push("username");
        }

        if (!password) {
            missing.push("password");
        }

        if (missing.length) {
            showMessage(`Nothing saved - fill in ${listFields(missing)}`, "error");
            return;
        }

        const response = await fetch("/store", {
            method: "POST",
            headers: jsonHeaders(),
            body: JSON.stringify({ site, username, password })
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            showMessage(data.error || "Could not save the entry", "error");
            return;
        }

        showMessage(`Saved ${site} to your vault`, "ok");
    });
});
