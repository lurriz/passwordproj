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

            const savePasswordBtn = document.getElementById("save-password");
            const passwordCurrent = document.getElementById("password-current");
            const passwordNew = document.getElementById("password-new");
            const passwordConfirm = document.getElementById("password-confirm");
            const passwordMessage = document.getElementById("password-message");

            const savePinBtn = document.getElementById("save-pin");
            const pinPassword = document.getElementById("pin-password");
            const pinNew = document.getElementById("pin-new");
            const pinConfirm = document.getElementById("pin-confirm");
            const pinMessage = document.getElementById("pin-message");

            function show(element, text, ok) {
                element.textContent = text;
                element.style.color = ok ? "#00ff55" : "red";
            }

            async function submitChange(url, body, message, fields) {
                const response = await fetch(url, {
                    method: "POST",
                    headers: jsonHeaders(),
                    body: JSON.stringify(body)
                });

                const data = await response.json().catch(() => ({}));

                if (!response.ok) {
                    show(message, data.error || "Something went wrong", false);
                    return false;
                }

                show(message, data.message, true);

                fields.forEach(field => {
                    field.value = "";
                });

                return true;
            }

            const emailInput = document.getElementById("email");
            const saveEmailBtn = document.getElementById("save-email");
            const sendRecoveryBtn = document.getElementById("send-recovery");
            const recoveryPassword = document.getElementById("recovery-password");
            const recoveryMessage = document.getElementById("recovery-message");
            const recoveryCode = document.getElementById("recovery-code");

            saveEmailBtn.addEventListener("click", async () => {
                if (!emailInput.value.trim()) {
                    show(recoveryMessage, "Enter an email address", false);
                    return;
                }

                if (!recoveryPassword.value) {
                    show(recoveryMessage, "Enter your password to change the recovery address", false);
                    return;
                }

                const response = await fetch("/set_email", {
                    method: "POST",
                    headers: jsonHeaders(),
                    body: JSON.stringify({
                        current_password: recoveryPassword.value,
                        email: emailInput.value.trim()
                    })
                });

                const data = await response.json().catch(() => ({}));

                recoveryPassword.value = "";

                if (!response.ok) {
                    recoveryCode.classList.add("hidden");
                    show(recoveryMessage, data.error || "Something went wrong", false);
                    return;
                }

                show(recoveryMessage, data.message, true);

                // Present only when the confirmation email could not be sent -
                // without it the address could never be confirmed.
                if (data.link) {
                    recoveryCode.textContent = data.link;
                    recoveryCode.classList.remove("hidden");
                } else {
                    recoveryCode.classList.add("hidden");
                }
            });

            sendRecoveryBtn.addEventListener("click", async () => {
                if (!recoveryPassword.value) {
                    show(recoveryMessage, "Enter your password", false);
                    return;
                }

                const response = await fetch("/send_recovery_code", {
                    method: "POST",
                    headers: jsonHeaders(),
                    body: JSON.stringify({ current_password: recoveryPassword.value })
                });

                const data = await response.json().catch(() => ({}));

                recoveryPassword.value = "";

                if (!response.ok) {
                    recoveryCode.classList.add("hidden");
                    show(recoveryMessage, data.error || "Something went wrong", false);
                    return;
                }

                show(recoveryMessage, data.message, true);

                // Only present when the email could not be sent, in which case
                // this is the only time the code will ever be visible.
                if (data.code) {
                    recoveryCode.textContent = data.code;
                    recoveryCode.classList.remove("hidden");
                } else {
                    recoveryCode.classList.add("hidden");
                }
            });

            savePasswordBtn.addEventListener("click", async () => {
                if (!passwordCurrent.value || !passwordNew.value) {
                    show(passwordMessage, "Fill in both password fields", false);
                    return;
                }

                if (passwordNew.value !== passwordConfirm.value) {
                    show(passwordMessage, "New passwords do not match", false);
                    return;
                }

                await submitChange(
                    "/change_password",
                    {
                        current_password: passwordCurrent.value,
                        new_password: passwordNew.value
                    },
                    passwordMessage,
                    [passwordCurrent, passwordNew, passwordConfirm]
                );
            });

            savePinBtn.addEventListener("click", async () => {
                if (!pinPassword.value || !pinNew.value) {
                    show(pinMessage, "Fill in your password and the new PIN", false);
                    return;
                }

                if (pinNew.value !== pinConfirm.value) {
                    show(pinMessage, "New PINs do not match", false);
                    return;
                }

                await submitChange(
                    "/change_pin",
                    {
                        current_password: pinPassword.value,
                        new_pin: pinNew.value
                    },
                    pinMessage,
                    [pinPassword, pinNew, pinConfirm]
                );
            });
        });
