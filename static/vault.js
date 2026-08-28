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

            const siteInput = document.getElementById("site");
            const usernameInput = document.getElementById("username");
            const container = document.getElementById("vault-data");
            const sidePanel = document.getElementById("entry-side-panel");
            const closeSidePanel = document.getElementById("close-side-panel");
            const copyButton = document.getElementById("copy-password");
            const sideMessage = document.getElementById("side-message");
            const revealPasswordBtn = document.getElementById("reveal-password");
            const editEntryBtn = document.getElementById("edit-entry");
            const editPopup = document.getElementById("edit-popup");
            const closeEditPopup = document.getElementById("close-edit-popup");
            const editOverlay = document.getElementById("edit-overlay");
            const saveEntryChangeBtn = document.getElementById("save-entry-change");
            const editMessage = document.getElementById("edit-message");
            const deletePopup = document.getElementById("delete-popup");
            const deleteEntryBtn = document.getElementById("delete-entry");
            const closeDeletePopup = document.getElementById("close-delete-popup");
            const confirmDeleteEntryBtn = document.getElementById("confirm-delete-entry");
            const cancelDeleteEntryBtn = document.getElementById("cancel-delete-entry");
            const deleteEntryId = document.getElementById("delete-entry-id");
            const deleteEntrySite = document.getElementById("delete-entry-site");
            const deleteEntryUsername = document.getElementById("delete-entry-username");
            const deleteEntryPassword = document.getElementById("delete-entry-password");
            const pinPopup = document.getElementById("pin-popup");
            const pinInput = document.getElementById("pin-input");
            const pinMessage = document.getElementById("pin-message");
            const submitPinBtn = document.getElementById("submit-pin");
            const closePinPopupBtn = document.getElementById("close-pin-popup");

            let selectedPassword = "";
            let searchTimeout;
            let selectedEntryId = null;
            let selectedEntryNumber = null;

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

            let pinResolver = null;

            closeSidePanel.addEventListener("click", () => {
                sidePanel.classList.add("hidden");
            });

            async function refreshSidePanel(entryId) {
                const response = await fetch(`/get_entry/${entryId}`);
                const entry = await response.json();

                selectedPassword = "";

                document.getElementById("entry-id").textContent = `ID: ${selectedEntryNumber}`;
                document.getElementById("entry-site").textContent = `Site: ${entry.site}`;
                document.getElementById("entry-username").textContent = `Username: ${entry.username}`;
                document.getElementById("entry-password").textContent = "Password: Hidden";

                revealPasswordBtn.textContent = "Show password";
                sideMessage.textContent = "";
            }

            document.addEventListener("click", (e) => {
                const editPopupOpen = !editPopup.classList.contains("hidden");
                const deletePopupOpen = !deletePopup.classList.contains("hidden");
                const pinPopupOpen = !pinPopup.classList.contains("hidden");

                if (editPopupOpen || deletePopupOpen || pinPopupOpen) {
                    return;
                }

                    const clickedInsidePanel = sidePanel.contains(e.target);
                    const clickedRow = e.target.closest(".vault-row");

                    if (
                        !sidePanel.classList.contains("hidden") &&
                        !clickedInsidePanel &&
                        !clickedRow
                    ) {
                        sidePanel.classList.add("hidden");
                    }
            });

            async function loadEntries(site = "", username = "") {
                const response = await fetch(
                    `/get_entries?site=${encodeURIComponent(site)}&username=${encodeURIComponent(username)}`
                );
                const data = await response.json();

                container.innerHTML = "";

                data.forEach(entry => {
                    const row = document.createElement("tr");

                    row.classList.add("vault-row");

                    row.dataset.id = entry.id;
                    row.dataset.number = entry.number;
                    row.dataset.site = entry.site;
                    row.dataset.username = entry.username;

                    const idCell = document.createElement("td");
                    idCell.textContent = entry.number;

                    const siteCell = document.createElement("td");
                    siteCell.textContent = entry.site;

                    const usernameCell = document.createElement("td");
                    usernameCell.textContent = entry.username;

                    row.appendChild(idCell);
                    row.appendChild(siteCell);
                    row.appendChild(usernameCell);

                    container.appendChild(row);
                });
            }

            loadEntries();

            function debounceSearch() {
                clearTimeout(searchTimeout);

                searchTimeout = setTimeout(() => {
                    loadEntries(siteInput.value, usernameInput.value);
                }, 300);
            }

            siteInput.addEventListener("input", debounceSearch);
            usernameInput.addEventListener("input", debounceSearch);

            container.addEventListener("click", async (e) => {
                const row = e.target.closest(".vault-row");

                if (!row) {
                    return;
                }

                const response = await fetch(`/get_entry/${row.dataset.id}`);
                const entry = await response.json();

                selectedPassword = "";
                selectedEntryId = entry.id;
                selectedEntryNumber = row.dataset.number;

                document.getElementById("entry-id").textContent = `ID: ${selectedEntryNumber}`;
                document.getElementById("entry-site").textContent = `Site: ${entry.site}`;
                document.getElementById("entry-username").textContent = `Username: ${entry.username}`;
                document.getElementById("entry-password").textContent = "Password: Hidden";

                revealPasswordBtn.textContent = "Show password";
                sideMessage.textContent = "";

                sidePanel.classList.remove("hidden");
            });

            function closePinPopup(password) {
                pinPopup.classList.add("hidden");
                editOverlay.classList.add("hidden");

                pinInput.value = "";
                pinMessage.textContent = "";

                const resolve = pinResolver;
                pinResolver = null;

                if (resolve) {
                    resolve(password);
                }
            }

            async function submitPin() {
                const pin = pinInput.value;

                if (!pin) {
                    pinMessage.textContent = "Enter a PIN";
                    pinMessage.style.color = "red";
                    return;
                }

                const response = await fetch(`/reveal_password/${selectedEntryId}`, {
                    method: "POST",
                    headers: jsonHeaders(),
                    body: JSON.stringify({ pin })
                });

                if (!response.ok) {
                    const error = await response.json().catch(() => ({}));

                    pinMessage.textContent = error.attempts_left
                        ? `Invalid PIN - ${error.attempts_left} attempts left`
                        : error.error || "Invalid PIN";

                    pinMessage.style.color = "red";
                    pinInput.value = "";
                    pinInput.focus();
                    return;
                }

                const data = await response.json();
                closePinPopup(data.password);
            }

            // Resolves with the plaintext password, or null if the user cancels.
            function getPasswordWithPin() {
                if (pinResolver) {
                    closePinPopup(null);
                }

                pinInput.value = "";
                pinMessage.textContent = "";

                pinPopup.classList.remove("hidden");
                editOverlay.classList.remove("hidden");
                pinInput.focus();

                return new Promise(resolve => {
                    pinResolver = resolve;
                });
            }

            submitPinBtn.addEventListener("click", submitPin);

            pinInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    submitPin();
                }
            });

            closePinPopupBtn.addEventListener("click", (e) => {
                e.stopPropagation();

                closePinPopup(null);
            });

            function isPasswordRevealed() {
                const passwordText = document.getElementById("entry-password");

                return passwordText.textContent !== "Password: Hidden";
            }

           revealPasswordBtn.addEventListener("click", async () => {
                const passwordText = document.getElementById("entry-password");

                if (passwordText.textContent !== "Password: Hidden") {
                    passwordText.textContent = "Password: Hidden";
                    revealPasswordBtn.textContent = "Show password";
                    selectedPassword = "";
                    return;
                }

                const password = await getPasswordWithPin();

                if (!password) {
                    return;
                }

                selectedPassword = password;
                passwordText.textContent = `Password: ${selectedPassword}`;
                revealPasswordBtn.textContent = "Hide password";
                sideMessage.textContent = "";
            });

            copyButton.addEventListener("click", async () => {
                const passwordText = document.getElementById("entry-password");

                if (passwordText.textContent === "Password: Hidden") {
                    const password = await getPasswordWithPin();

                    if (!password) {
                        return;
                    }

                    selectedPassword = password;
                }

                const copied = selectedPassword;

                try {
                    await navigator.clipboard.writeText(copied);
                } catch (refused) {
                    sideMessage.textContent = "Could not reach the clipboard";
                    sideMessage.style.color = "var(--danger)";
                    return;
                }

                clearClipboardLater(copied);

                sideMessage.textContent = "Copied - clipboard clears in 30s";
                sideMessage.style.color = "var(--ok)";

                setTimeout(() => {
                    sideMessage.textContent = "";
                }, 4000);
            });

           editEntryBtn.addEventListener("click", async () => {
                if (!isPasswordRevealed()) {
                    const password = await getPasswordWithPin();

                    if (!password) {
                        return;
                    }

                    selectedPassword = password;
                }

                document.getElementById("edit-entry-id").textContent =
                    document.getElementById("entry-id").textContent;

                document.getElementById("site-edit").value =
                    document.getElementById("entry-site").textContent.replace("Site: ", "");

                document.getElementById("username-edit").value =
                    document.getElementById("entry-username").textContent.replace("Username: ", "");

                document.getElementById("password-edit").value = selectedPassword;

                editMessage.textContent = "";

                editPopup.classList.remove("hidden");
                editOverlay.classList.remove("hidden");
            });

            function hideEditPopup() {
                editPopup.classList.add("hidden");
                editOverlay.classList.add("hidden");
            }

           closeEditPopup.addEventListener("click", (e) => {
                e.stopPropagation();

                hideEditPopup();
            });

           editOverlay.addEventListener("click", (e) => {
                e.stopPropagation();

                if (!pinPopup.classList.contains("hidden")) {
                    closePinPopup(null);
                    return;
                }

                editPopup.classList.add("hidden");
                deletePopup.classList.add("hidden");
                editOverlay.classList.add("hidden");
            });

            saveEntryChangeBtn.addEventListener("click", async () => {
                const site = document.getElementById("site-edit").value;
                const username = document.getElementById("username-edit").value;
                const password = document.getElementById("password-edit").value;

                const missing = [];

                if (!site.trim()) {
                    missing.push("site");
                }

                if (!username.trim()) {
                    missing.push("username");
                }

                if (!password.trim()) {
                    missing.push("password");
                }

                // alert() is suppressed outright in embedded browsers, so the
                // button appeared to do nothing at all.
                if (missing.length) {
                    editMessage.textContent = missing.length > 1
                        ? `Fill in ${missing.slice(0, -1).join(", ")} and ${missing[missing.length - 1]}`
                        : `Fill in ${missing[0]}`;
                    editMessage.style.color = "var(--danger)";
                    return;
                }

                const response = await fetch(`/update_entry/${selectedEntryId}`, {
                    method: "POST",
                    headers: jsonHeaders(),
                    body: JSON.stringify({ site, username, password })
                });

                if (!response.ok) {
                    const problem = await response.json().catch(() => ({}));
                    editMessage.textContent = problem.error || "Could not save the changes";
                    editMessage.style.color = "var(--danger)";
                    return;
                }

                hideEditPopup();

                await refreshSidePanel(selectedEntryId);
                await loadEntries(siteInput.value, usernameInput.value);
            });
            
            deleteEntryBtn.addEventListener("click", async () => {
                if (!isPasswordRevealed()) {
                    const password = await getPasswordWithPin();

                    if (!password) {
                        return;
                    }

                    selectedPassword = password;
                }

                deleteEntryId.textContent = document.getElementById("entry-id").textContent;
                deleteEntrySite.textContent = document.getElementById("entry-site").textContent;
                deleteEntryUsername.textContent = document.getElementById("entry-username").textContent;
                deleteEntryPassword.textContent = `Password: ${selectedPassword}`;

                deletePopup.classList.remove("hidden");
                editOverlay.classList.remove("hidden");
            });

            function hideDeletePopup() {
                deletePopup.classList.add("hidden");
                editOverlay.classList.add("hidden");
            }

            closeDeletePopup.addEventListener("click", (e) => {
                e.stopPropagation();

                hideDeletePopup();
            });

            cancelDeleteEntryBtn.addEventListener("click", (e) => {
                e.stopPropagation();

                hideDeletePopup();
            });
            
            confirmDeleteEntryBtn.addEventListener("click", async () => {
                await fetch(`/delete_entry/${selectedEntryId}`, {
                    method: "POST",
                    headers: { "X-CSRF-Token": csrfToken }
                });

                deletePopup.classList.add("hidden");
                editOverlay.classList.add("hidden");
                sidePanel.classList.add("hidden");

                await loadEntries(siteInput.value, usernameInput.value);
            });

            // Escape peels one layer at a time: popup first, then the side panel.
            document.addEventListener("keydown", (e) => {
                if (e.key !== "Escape") {
                    return;
                }

                if (!pinPopup.classList.contains("hidden")) {
                    closePinPopup(null);
                    return;
                }

                if (!editPopup.classList.contains("hidden")) {
                    hideEditPopup();
                    return;
                }

                if (!deletePopup.classList.contains("hidden")) {
                    hideDeletePopup();
                    return;
                }

                if (!sidePanel.classList.contains("hidden")) {
                    sidePanel.classList.add("hidden");
                }
            });

        });