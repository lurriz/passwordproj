document.addEventListener("DOMContentLoaded", () => {
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
            const deletePopup = document.getElementById("delete-popup");
            const deleteEntryBtn = document.getElementById("delete-entry");
            const closeDeletePopup = document.getElementById("close-delete-popup");
            const confirmDeleteEntryBtn = document.getElementById("confirm-delete-entry");
            const deleteEntryId = document.getElementById("delete-entry-id");
            const deleteEntrySite = document.getElementById("delete-entry-site");
            const deleteEntryUsername = document.getElementById("delete-entry-username");
            const deleteEntryPassword = document.getElementById("delete-entry-password");

            let selectedPassword = "";
            let searchTimeout;
            let selectedEntryId = null;

            closeSidePanel.addEventListener("click", () => {
                sidePanel.classList.add("hidden");
            });

            async function refreshSidePanel(entryId) {
                const response = await fetch(`/get_entry/${entryId}`);
                const entry = await response.json();

                selectedPassword = entry.password;

                document.getElementById("entry-id").textContent = `ID: ${entry.id}`;
                document.getElementById("entry-site").textContent = `Site: ${entry.site}`;
                document.getElementById("entry-username").textContent = `Username: ${entry.username}`;
                document.getElementById("entry-password").textContent = "Password: Hidden";

                revealPasswordBtn.textContent = "Reveal password";
                sideMessage.textContent = "";
}

            document.addEventListener("click", (e) => {
                const editPopupOpen = !editPopup.classList.contains("hidden");
                const deletePopupOpen = !deletePopup.classList.contains("hidden");

                if (editPopupOpen || deletePopupOpen) {
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
                    row.dataset.site = entry.site;
                    row.dataset.username = entry.username;

                    row.innerHTML = `
                        <td>${entry.id}</td>
                        <td>${entry.site}</td>
                        <td>${entry.username}</td>
                    `;

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

                selectedPassword = entry.password;
                selectedEntryId = entry.id;

                document.getElementById("entry-id").textContent = `ID: ${entry.id}`;
                document.getElementById("entry-site").textContent = `Site: ${entry.site}`;
                document.getElementById("entry-username").textContent = `Username: ${entry.username}`;
                document.getElementById("entry-password").textContent = "Password: Hidden";

                revealPasswordBtn.textContent = "Reveal password";
                sideMessage.textContent = "";

                sidePanel.classList.remove("hidden");
            });

            revealPasswordBtn.addEventListener("click", () => {
                const passwordText = document.getElementById("entry-password");

                if (passwordText.textContent === "Password: Hidden") {
                    passwordText.textContent = `Password: ${selectedPassword}`;
                    revealPasswordBtn.textContent = "Hide password";
                } else {
                    passwordText.textContent = "Password: Hidden";
                    revealPasswordBtn.textContent = "Reveal password";
                }
            });

            copyButton.addEventListener("click", () => {
                if (!selectedPassword.trim()) {
                    sideMessage.textContent = "No password selected";
                    sideMessage.style.color = "red";
                    return;
                }
                
                navigator.clipboard.writeText(selectedPassword);

                sideMessage.textContent = "Password copied!";
                sideMessage.style.color = "#00ff55";

                setTimeout(() => {

                }, 1000);
            });

            editEntryBtn.addEventListener("click", () => {
                document.getElementById("edit-entry-id").textContent =
                    document.getElementById("entry-id").textContent;

                document.getElementById("site-edit").value =
                    document.getElementById("entry-site").textContent.replace("Site: ", "");

                document.getElementById("username-edit").value =
                    document.getElementById("entry-username").textContent.replace("Username: ", "");

                document.getElementById("password-edit").value = selectedPassword;

                editPopup.classList.remove("hidden");
                editOverlay.classList.remove("hidden");
            });

           closeEditPopup.addEventListener("click", (e) => {
                e.stopPropagation();

                editPopup.classList.add("hidden");
                editOverlay.classList.add("hidden");
            });

           editOverlay.addEventListener("click", (e) => {
                e.stopPropagation();

                editPopup.classList.add("hidden");
                deletePopup.classList.add("hidden");
                editOverlay.classList.add("hidden");
            });

            saveEntryChangeBtn.addEventListener("click", async () => {
                const site = document.getElementById("site-edit").value;
                const username = document.getElementById("username-edit").value;
                const password = document.getElementById("password-edit").value;

                if (!site.trim() || !username.trim() || !password.trim()) {
                    alert("All fields are required");
                    return;
                }

                await fetch(`/update_entry/${selectedEntryId}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ site, username, password })
                });

                editPopup.classList.add("hidden");
                editOverlay.classList.add("hidden");

                await refreshSidePanel(selectedEntryId);
                await loadEntries(siteInput.value, usernameInput.value);
            });
            
            deleteEntryBtn.addEventListener("click", () => {
                deleteEntryId.textContent = document.getElementById("entry-id").textContent;
                deleteEntrySite.textContent = document.getElementById("entry-site").textContent;
                deleteEntryUsername.textContent = document.getElementById("entry-username").textContent;
                deleteEntryPassword.textContent = `Password: ${selectedPassword}`;

                deletePopup.classList.remove("hidden");
                editOverlay.classList.remove("hidden");
            });

            closeDeletePopup.addEventListener("click", (e) => {
                e.stopPropagation();

                deletePopup.classList.add("hidden");
                editOverlay.classList.add("hidden");
            });
            
            confirmDeleteEntryBtn.addEventListener("click", async () => {
                await fetch(`/delete_entry/${selectedEntryId}`, {
                    method: "POST"
                });

                deletePopup.classList.add("hidden");
                editOverlay.classList.add("hidden");
                sidePanel.classList.add("hidden");

                await loadEntries(siteInput.value, usernameInput.value);
            });

        });