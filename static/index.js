  document.addEventListener("DOMContentLoaded", () => {
            const generateBtn = document.getElementById("generate");
            const copyBtn = document.getElementById("copy-clipboard");
            const output = document.getElementById("output");
            const lengthInput = document.getElementById("length");
            const saveBtn = document.getElementById("save-to-DB")

            generateBtn.addEventListener("click", async () => {
                const length = lengthInput.value || 16;

                const response = await fetch(`/generate?length=${length}`);
                const password = await response.text();

                output.value = password;
            });

            copyBtn.addEventListener("click", () => {
                const password = output.value

                    if(!password.trim()){
                    const msg = document.createElement("div");
                    msg.textContent = "Password is empty!";
                    msg.style.position = "absolute";
                    msg.style.top = "145px";
                    msg.style.color = "red";

                    document.body.appendChild(msg);

                    setTimeout(() => {
                        msg.remove();
                    }, 1000);
                    return;
                 }

                navigator.clipboard.writeText(password);

                const msg = document.createElement("div");
                msg.textContent = "Copied!";
                msg.style.position = "absolute";
                msg.style.top = "145px";
                msg.style.color = "green";

                document.body.appendChild(msg);

                setTimeout(() => {
                    msg.remove();
                }, 1000);
            }); 

            saveBtn.addEventListener("click", async () => {
                const site = document.getElementById("site").value;
                const username = document.getElementById("username").value;
                const password = document.getElementById("output").value;

                  if (!password ||!site ||!username) {
                    alert("Fields are missing");
                    return;
                }

                const response = await fetch("/store", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        site: site,
                        username: username,
                        password: password
                    })
                });
                  const msg = document.createElement("div");
                msg.textContent = "Saved!";
                msg.style.position = "absolute";
                msg.style.top = "140px";
                msg.style.color = "white";

                document.body.appendChild(msg);

                setTimeout(() => {
                    msg.remove();
                }, 1000);
              
            });
            
            
        });