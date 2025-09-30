const API_URL = "http://localhost:3000";
let accessToken = null;

function log(msg, type = "") {
  const logDiv = document.getElementById("log");
  const className = type === "success" ? "success" : type === "error" ? "error" : "";
  logDiv.innerHTML += `<div class="${className}">${msg}</div>`;
  logDiv.scrollTop = logDiv.scrollHeight;
}

// Restore session on page load using /refresh
window.addEventListener("load", async () => {
  try {
    const res = await fetch(`${API_URL}/refresh`, {
      method: "POST",
      credentials: "include"
    });
    const data = await res.json();
    if (res.ok) {
      accessToken = data.accessToken;
      log("Session restored! Access token: " + accessToken, "success");
    } else {
      log("Session not restored: " + (data.error || "Please login."), "error");
    }
  } catch (err) {
    log("Session restore error: " + err.message, "error");
  }
});

document.getElementById("signupForm").addEventListener("submit", function (e) {
  e.preventDefault();
  const formData = new FormData(e.target);
  fetch(`${API_URL}/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(formData)),
    credentials: "include"
  })
    .then(res => res.json().then(json => ({ status: res.status, json })))
    .then(({ status, json }) => {
      if (status === 200) {
        log("Signup success: " + JSON.stringify(json), "success");
      } else {
        log("Signup error: " + (json.error || JSON.stringify(json)), "error");
      }
    })
    .catch(err => log("Signup network error: " + err.message, "error"));
});

document.getElementById("loginForm").addEventListener("submit", function (e) {
  e.preventDefault();
  const formData = new FormData(e.target);
  fetch(`${API_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(formData)),
    credentials: "include"
  })
    .then(res => res.json().then(json => ({ status: res.status, json })))
    .then(({ status, json }) => {
      if (status === 200) {
        accessToken = json.accessToken;
        log("Login success: " + JSON.stringify(json), "success");
      } else {
        log("Login error: " + (json.error || JSON.stringify(json)), "error");
      }
    })
    .catch(err => log("Login network error: " + err.message, "error"));
});

document.getElementById("logoutForm").addEventListener("submit", function (e) {
  e.preventDefault();
  fetch(`${API_URL}/logout`, {
    method: "POST",
    credentials: "include"
  })
    .then(res => res.json().then(json => ({ status: res.status, json })))
    .then(({ status, json }) => {
      if (status === 200) {
        accessToken = null;
        log("Logout success: " + JSON.stringify(json), "success");
      } else {
        log("Logout error: " + (json.error || JSON.stringify(json)), "error");
      }
    })
    .catch(err => log("Logout network error: " + err.message, "error"));
});
