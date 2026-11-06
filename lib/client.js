// dsh-password-login — browser half: one section inside the DSH settings dialog.
// It talks to the host half over JSON routes under the login path, which keep
// the same signed-cookie check the login page uses.
window.__ModuleLoader__.load({
	id: "dsh-password-login",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		const React = require("react");
		const runtime = require("react/jsx-runtime");
		const jsx = runtime.jsx || (runtime.default && runtime.default.jsx);

		const API = "/__dsh_login/api";
		const LOGIN = "/__dsh_login";

		const h = (type, props, ...children) => {
			const next = { ...(props || {}) };
			if (children.length === 1) next.children = children[0];
			else if (children.length > 1) next.children = children;
			return jsx(type, next);
		};

		const CSS = [
			".dpl-wrap{display:flex;flex-direction:column;gap:18px;color:var(--dsw-alias-label-primary,#0f1115);font-size:14px}",
			".dpl-title{margin:0;font-size:16px;font-weight:600}",
			".dpl-hint{margin:0;color:var(--dsw-alias-label-secondary,#61666b);font-size:12.5px;line-height:1.6}",
			".dpl-card{border:1px solid var(--dsw-alias-border-l2,#e1e5ee);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:10px;background:var(--dsw-alias-bg-layer-1,#fff)}",
			".dpl-row{display:flex;gap:12px}.dpl-row>*{flex:1;min-width:0}",
			".dpl-label{font-size:12.5px;color:var(--dsw-alias-label-secondary,#61666b);margin-bottom:6px;display:block}",
			".dpl-input,.dpl-select,.dpl-area{width:100%;box-sizing:border-box;padding:8px 10px;border-radius:8px;border:1px solid var(--dsw-alias-border-l2,#e1e5ee);background:var(--dsw-alias-bg-layer-1,#fff);color:inherit;font:inherit;font-size:13.5px}",
			".dpl-area{min-height:64px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px}",
			".dpl-input:focus,.dpl-select:focus,.dpl-area:focus{outline:none;border-color:#5686fe;box-shadow:0 0 0 3px rgba(86,134,254,.16)}",
			".dpl-actions{display:flex;align-items:center;gap:10px;margin-top:2px}",
			".dpl-btn{padding:7px 14px;border:0;border-radius:8px;background:#5686fe;color:#fff;font:inherit;font-size:13px;font-weight:600;cursor:pointer}",
			".dpl-btn:hover{background:#4176e6}.dpl-btn:disabled{opacity:.55;cursor:default}",
			".dpl-btn.ghost{background:transparent;color:var(--dsw-alias-label-secondary,#61666b);border:1px solid var(--dsw-alias-border-l2,#e1e5ee)}",
			".dpl-msg{font-size:12.5px}.dpl-msg.ok{color:#067647}.dpl-msg.err{color:#b42318}",
			".dpl-table{width:100%;border-collapse:collapse;font-size:12px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}",
			".dpl-table th,.dpl-table td{text-align:left;padding:5px 6px;border-bottom:1px solid var(--dsw-alias-border-l1,#edf0f4);color:var(--dsw-alias-label-secondary,#61666b);white-space:nowrap}",
			".dpl-table td:last-child,.dpl-table th:last-child{white-space:normal}",
			".dpl-table th{color:var(--dsw-alias-label-tertiary,#979da6);font-weight:600}",
			".dpl-pass{color:#067647}.dpl-fail{color:#b42318}",
			".dpl-foot{font-size:12px;color:var(--dsw-alias-label-tertiary,#979da6);line-height:1.9}",
			".dpl-foot code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}",
			"a.dpl-link{color:#4176e6;text-decoration:none}a.dpl-link:hover{text-decoration:underline}",
		].join("");

		function ensureStyles() {
			if (document.getElementById("dpl-settings-style")) return;
			const style = document.createElement("style");
			style.id = "dpl-settings-style";
			style.textContent = CSS;
			document.head.appendChild(style);
		}

		async function request(path, init) {
			const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...(init || {}) });
			let data = {};
			try {
				data = await response.json();
			} catch {
				data = {};
			}
			if (response.status === 401) {
				const target = (data && data.loginPath) || LOGIN;
				const next = globalThis.location.pathname + globalThis.location.search;
				globalThis.location.href = target + "?next=" + encodeURIComponent(next);
				throw new Error("未登录");
			}
			if (!response.ok) throw new Error((data && data.message) || "请求失败（" + String(response.status) + "）");
			return data;
		}

		const MODE_HINTS = {
			strict: "只接受本站来源的表单提交；浏览器的 Origin / Sec-Fetch-Site 必须和本站一致。",
			allowlist: "本站来源，加上下面列出的来源；用于从别的端口或域名登录同一个实例。",
			off: "完全不校验来源，只校验密码。密码正确才放行，cookie 仍是 HttpOnly + SameSite=Strict。",
		};

		function Section() {
			React.useEffect(() => {
				ensureStyles();
			}, []);
			const [state, setState] = React.useState(null);
			const [draft, setDraft] = React.useState(null);
			const [password, setPassword] = React.useState({ next: "", confirm: "" });
			const [status, setStatus] = React.useState({ kind: "", text: "" });
			const [busy, setBusy] = React.useState(false);

			const load = React.useCallback(async () => {
				try {
					const data = await request(API + "/state");
					setState(data);
					setDraft(data.settings);
				} catch (error) {
					setStatus({ kind: "err", text: String((error && error.message) || error) });
				}
			}, []);

			React.useEffect(() => {
				load();
			}, [load]);

			const saveSettings = async () => {
				if (!draft) return;
				setBusy(true);
				setStatus({ kind: "", text: "" });
				try {
					const data = await request(API + "/settings", {
						method: "POST",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({
							crossOrigin: draft.crossOrigin,
							allowedOrigins: draft.allowedOrigins,
							maxAttempts: Number(draft.maxAttempts),
							lockMinutes: Number(draft.lockMinutes),
							cookieMaxAgeDays: Number(draft.cookieMaxAgeDays),
						}),
					});
					setState((prev) => ({ ...prev, settings: data.settings }));
					setDraft(data.settings);
					setStatus({ kind: "ok", text: "设置已保存，立即生效" });
				} catch (error) {
					setStatus({ kind: "err", text: String((error && error.message) || error) });
				} finally {
					setBusy(false);
				}
			};

			const savePassword = async () => {
				setBusy(true);
				setStatus({ kind: "", text: "" });
				try {
					const data = await request(API + "/password", {
						method: "POST",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({ next: password.next, confirm: password.confirm }),
					});
					setPassword({ next: "", confirm: "" });
					setState((prev) => (prev ? { ...prev, passwordUpdatedAt: data.passwordUpdatedAt } : prev));
					setStatus({ kind: "ok", text: "密码已更新" });
				} catch (error) {
					setStatus({ kind: "err", text: String((error && error.message) || error) });
				} finally {
					setBusy(false);
				}
			};

			const message = status.text
				? h("div", { className: "dpl-msg " + (status.kind === "ok" ? "ok" : "err") }, status.text)
				: null;

			if (!draft) {
				return h("div", { className: "dpl-wrap" },
					h("h3", { className: "dpl-title" }, "登录安全"),
					h("p", { className: "dpl-hint" }, state === null ? "读取设置…" : "没有读到设置"),
					message);
			}

			const field = (label, control) => h("div", null,
				h("label", { className: "dpl-label" }, label),
				control);

			const events = (state && state.events) || [];
			const rows = events.length === 0
				? [h("tr", { key: "empty" }, h("td", { colSpan: 4 }, "暂无记录"))]
				: events.map((entry, index) => h("tr", { key: String(index) },
					h("td", null, entry.at),
					h("td", null, entry.ip),
					h("td", { className: entry.ok ? "dpl-pass" : "dpl-fail" }, entry.ok ? "成功" : "拒绝"),
					h("td", null, entry.detail || "")));

			return h("div", { className: "dpl-wrap" },
				h("div", null,
					h("h3", { className: "dpl-title" }, "登录安全"),
					h("p", { className: "dpl-hint" }, "密码登录入口 " + ((state && state.loginPath) || LOGIN) + " · 由 dsh-password-login 插件提供")),
				message,
				h("div", { className: "dpl-card" },
					h("div", { className: "dpl-label" }, "来源校验（CORS）"),
					h("p", { className: "dpl-hint" }, MODE_HINTS[draft.crossOrigin] || ""),
					field("跨站登录策略", h("select", {
						className: "dpl-select",
						value: draft.crossOrigin,
						onChange: (event) => setDraft({ ...draft, crossOrigin: event.target.value }),
					},
					h("option", { value: "strict" }, "strict — 只接受本站来源（默认）"),
					h("option", { value: "allowlist" }, "allowlist — 本站来源 + 白名单"),
					h("option", { value: "off" }, "off — 不校验来源，只校验密码"))),
					field("允许的来源（每行一个，含协议与端口）", h("textarea", {
						className: "dpl-area",
						spellCheck: false,
						placeholder: "http://192.168.1.10:8080",
						value: (draft.allowedOrigins || []).join("\n"),
						onChange: (event) => setDraft({
							...draft,
							allowedOrigins: event.target.value.split("\n").map((line) => line.trim()).filter((line) => line.length > 0),
						}),
					})),
					h("div", { className: "dpl-row" },
						field("失败次数上限", h("input", {
							className: "dpl-input",
							type: "number",
							min: 1,
							max: 100,
							value: draft.maxAttempts,
							onChange: (event) => setDraft({ ...draft, maxAttempts: event.target.value }),
						})),
						field("锁定时长（分钟）", h("input", {
							className: "dpl-input",
							type: "number",
							min: 1,
							max: 1440,
							value: draft.lockMinutes,
							onChange: (event) => setDraft({ ...draft, lockMinutes: event.target.value }),
						}))),
					field("免登录天数", h("input", {
						className: "dpl-input",
						type: "number",
						min: 1,
						max: 3650,
						value: draft.cookieMaxAgeDays,
						onChange: (event) => setDraft({ ...draft, cookieMaxAgeDays: event.target.value }),
					})),
					h("div", { className: "dpl-actions" },
						h("button", { className: "dpl-btn", type: "button", disabled: busy, onClick: saveSettings }, "保存设置"))),
				h("div", { className: "dpl-card" },
					h("div", { className: "dpl-label" }, "修改密码"),
					h("p", { className: "dpl-hint" }, "已登录即可修改，不需要原密码。改动立即生效，不需要重启。"),
					field("新密码（至少 8 位）", h("input", {
						className: "dpl-input",
						type: "password",
						autoComplete: "new-password",
						value: password.next,
						onChange: (event) => setPassword({ ...password, next: event.target.value }),
					})),
					field("再输一次新密码", h("input", {
						className: "dpl-input",
						type: "password",
						autoComplete: "new-password",
						value: password.confirm,
						onChange: (event) => setPassword({ ...password, confirm: event.target.value }),
					})),
					h("div", { className: "dpl-actions" },
						h("button", {
							className: "dpl-btn",
							type: "button",
							disabled: busy || password.next.length < 8,
							onClick: savePassword,
						}, "更新密码"))),
				h("div", { className: "dpl-card" },
					h("div", { className: "dpl-label" }, "最近登录尝试"),
					h("table", { className: "dpl-table" },
						h("thead", null, h("tr", null,
							h("th", null, "时间"), h("th", null, "来源 IP"), h("th", null, "结果"), h("th", null, "备注"))),
						h("tbody", null, rows))),
				h("div", { className: "dpl-foot" },
					"密码文件 " + ((state && state.passwordFile) || "") +
					(state && state.passwordUpdatedAt ? " · 更新于 " + state.passwordUpdatedAt : "") +
					" · ",
					h("a", { className: "dpl-link", href: "/__dsh_login/logout" }, "退出登录")));
		}

		const inject = ["slots"];

		function apply(ctx) {
			try {
				ctx.slots.inject("settings.section", () => ctx.slots.register({
					name: "settings.section",
					id: "password-login",
					order: 90,
					label: () => "登录安全",
				}, Section));
			} catch (error) {
				console.error("dsh-password-login: settings section registration failed", error);
			}
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
