const $ = (id) => document.getElementById(id);
let result = null,
  selected = 0;
const names = {
  rsa_bits: "Kích thước khóa RSA (bit)",
  certificate_bytes: "Chứng chỉ (byte)",
  subject: "Chủ thể",
  certificate_sha256: "SHA-256 chứng chỉ",
  note: "Ghi chú",
  signature: "Chữ ký",
  issuer: "CA phát hành",
  hostname: "Tên máy chủ",
  validity: "Thời hạn",
  client_random: "Client random",
  server_random: "Server random",
  premaster_secret: "Bí mật tiền chủ",
  rsa_ciphertext: "Bí mật đã mã hóa bằng RSA",
  rsa_ciphertext_bytes: "Độ dài bản mã RSA (byte)",
  matches_A: "Khớp bí mật của A",
  A_public_x25519: "Khóa công khai X25519 của A",
  B_public_x25519: "Khóa công khai X25519 của B",
  signature_bytes: "Kích thước chữ ký (byte)",
  hash: "Hàm băm",
  A_shared_secret: "Bí mật chung phía A",
  B_shared_secret: "Bí mật chung phía B",
  matches: "Hai bí mật khớp",
  algorithm: "Thuật toán dẫn xuất",
  master_secret_A: "Master secret phía A",
  master_secret_B: "Master secret phía B",
  A_to_B_key_A: "Khóa A → B phía A",
  A_to_B_key_B: "Khóa A → B phía B",
  keys_match: "Hai khóa khớp",
  plaintext_utf8: "Bản rõ UTF-8",
  plaintext_hex: "Bản rõ (hex)",
  nonce: "Nonce",
  aad_utf8: "Dữ liệu xác thực bổ sung (AAD)",
  ciphertext_hex: "Bản mã (hex)",
  tag_hex: "Tag xác thực (hex)",
  plaintext_bytes: "Bản rõ (byte)",
  ciphertext_bytes: "Bản mã (byte)",
  tag_bytes: "Tag (byte)",
  address: "Địa chỉ",
  frame_hex: "Khung gửi đi (hex)",
  frame_bytes: "Độ dài khung (byte)",
  length_prefix_bytes: "Tiền tố độ dài (byte)",
  nonce_bytes: "Nonce (byte)",
  tampered: "Đã sửa tag",
  result: "Kết quả",
  tag: "Xác thực tag",
  matches_original: "Khớp thông điệp ban đầu",
};
const descriptions = [
  "CA RSA tạo chứng chỉ thử nghiệm cho khóa xác thực của B.",
  "A kiểm tra chữ ký CA, tên B.local và thời hạn của chứng chỉ.",
  "A và B thiết lập bí mật ban đầu bằng phương pháp đã chọn.",
  "Bí mật được kiểm tra hoặc tính độc lập tại hai phía.",
  "A và B tự dẫn xuất khóa phiên từ cùng bí mật; giá trị phải khớp.",
  "A dùng khóa phiên và nonce để mã hóa thông điệp và tạo tag xác thực.",
  "Khung chứa nonce, bản mã và tag được chuyển qua TCP loopback.",
  "B kiểm tra tag trước khi chấp nhận bản rõ.",
];
const profiles = {
  "SSL 2.0": {
    exchange: ["RSA key transport"],
    suites: [
      ["RC4-128", "MD5"],
      ["3DES-CBC", "MD5"],
    ],
  },
  "SSL 3.0": {
    exchange: ["RSA key transport"],
    suites: [
      ["RC4-128", "MD5"],
      ["3DES-CBC", "SHA-1"],
    ],
  },
  "TLS 1.0": {
    exchange: ["RSA key transport", "DHE 2048", "ECDHE P-256"],
    suites: [
      ["AES-128-CBC", "SHA-1"],
      ["AES-256-CBC", "SHA-1"],
    ],
  },
  "TLS 1.1": {
    exchange: ["RSA key transport", "DHE 2048", "ECDHE P-256"],
    suites: [
      ["AES-128-CBC", "SHA-1"],
      ["AES-256-CBC", "SHA-1"],
    ],
  },
  "TLS 1.2": {
    exchange: ["RSA key transport", "DHE 2048", "ECDHE X25519", "ECDHE P-256"],
    suites: [
      ["AES-128-GCM", "SHA-256"],
      ["AES-256-GCM", "SHA-384"],
    ],
  },
  "TLS 1.3": {
    exchange: ["ECDHE X25519", "ECDHE P-256", "DHE ffdhe2048"],
    suites: [
      ["AES-128-GCM", "SHA-256"],
      ["AES-256-GCM", "SHA-384"],
    ],
  },
};
function buttonLabel() {
  return $("mode").value === "real" ? "Chạy kết nối thực" : "Chạy mô hình";
}
function options(id, values, preferred) {
  const node = $(id);
  node.replaceChildren(...values.map((v) => new Option(v, v)));
  if (values.includes(preferred)) node.value = preferred;
}
function updateChoices(source) {
  const real = $("mode").value === "real";
  if (
    !real &&
    source === "mode" &&
    !["TLS 1.2", "TLS 1.3", "SSL 1.0"].includes($("version").value)
  )
    $("version").value = "TLS 1.2";
  for (const opt of $("version").options)
    opt.disabled =
      !real && !["SSL 1.0", "TLS 1.2", "TLS 1.3"].includes(opt.value);
  const v = $("version").value,
    historical = v === "SSL 1.0",
    legacy = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"].includes(v),
    profile = profiles[v];
  $("mode-title").textContent = historical
    ? "✳ SSL 1.0 · lịch sử"
    : real
      ? `✳ ${v} thực`
      : "✳ Mô hình học tập";
  $("mode-description").textContent = historical
    ? "Chưa có đặc tả hoặc triển khai công khai được xác minh; không thể chạy hoặc gán cipher suite."
    : !real
      ? "Quan sát phép toán mật mã thật trong mô hình; handshake và khung truyền không phải TLS thực."
      : legacy
        ? "Chạy bằng OpenSSL 1.0.2u trong container cô lập. Một số metric không thể tách riêng."
        : "OpenSSL thực hiện handshake và mã hóa; log hiển thị TLS record, khóa phiên nằm trong thư viện.";
  for (const id of ["exchange", "authentication", "cipher", "hash", "rsa_bits"])
    $(id).disabled = historical;
  if (historical) {
    for (const id of [
      "exchange",
      "authentication",
      "cipher",
      "hash",
      "rsa_bits",
    ])
      options(id, ["—"], "—");
  }
  if (profile) {
    if ($("rsa_bits").value === "—")
      options("rsa_bits", ["2048", "3072"], "2048");
    const oldCipher = $("cipher").value,
      oldExchange = $("exchange").value,
      oldHash = $("hash").value,
      oldAuth = $("authentication").value;
    options("exchange", profile.exchange, oldExchange);
    const authChoices =
      (["TLS 1.0", "TLS 1.1", "TLS 1.2"].includes(v) &&
        $("exchange").value.startsWith("ECDHE")) ||
      v === "TLS 1.3"
        ? ["RSA", "ECDSA P-256"]
        : ["RSA"];
    options("authentication", authChoices, oldAuth);
    let chosen =
      profile.suites.find((s) => source === "hash" && s[1] === oldHash) ||
      profile.suites.find((s) => s[0] === oldCipher) ||
      profile.suites[0];
    options(
      "cipher",
      profile.suites.map((s) => s[0]),
      chosen[0],
    );
    options("hash", [...new Set(profile.suites.map((s) => s[1]))], chosen[1]);
  }
  $("rsa-label").firstChild.nodeValue = $("authentication").value.startsWith(
    "ECDSA",
  )
    ? "Khóa CA RSA (bit)"
    : "Kích thước khóa RSA";
  $("rsa-label").style.display =
    legacy && $("authentication").value.startsWith("ECDSA") ? "none" : "";
  $("auth-hint").textContent = historical
    ? ""
    : v.startsWith("SSL")
      ? "Backend lịch sử hiện chỉ có cấu hình RSA."
      : v !== "TLS 1.3" && !$("exchange").value.startsWith("ECDHE")
        ? "Chọn ECDHE để dùng chứng chỉ ECDSA."
        : "Chọn RSA hoặc ECDSA cho chứng chỉ server.";
  $("run").disabled = historical;
  $("run").innerHTML = buttonLabel() + " <span>→</span>";
  $("tamper").disabled = historical || (real && legacy);
  if ($("tamper").disabled) $("tamper").checked = false;
  if (historical)
    $("status").textContent =
      "SSL 1.0 chưa có triển khai công khai được xác minh để chạy.";
  if (result) {
    $("status").textContent = "Cấu hình đã đổi · Chạy lại để cập nhật kết quả";
    $("result-badge").textContent = "KẾT QUẢ CŨ";
    $("result-badge").className = "badge pending";
  }
}
[
  "mode",
  "version",
  "exchange",
  "cipher",
  "hash",
  "rsa_bits",
  "authentication",
].forEach((id) => $(id).addEventListener("change", () => updateChoices(id)));
$("message").addEventListener("input", () => {
  $("message-size").textContent =
    `${new TextEncoder().encode($("message").value).length} byte`;
  if (result)
    $("status").textContent =
      "Thông điệp đã đổi · Chạy lại để cập nhật kết quả";
});
$("tamper").addEventListener("change", () => {
  if (result)
    $("status").textContent = "Tùy chọn đã đổi · Chạy lại để cập nhật kết quả";
});
function metric(label, value, unit, note) {
  const a = document.createElement("article"),
    s = document.createElement("span"),
    b = document.createElement("b"),
    sm = document.createElement("small"),
    e = document.createElement("em");
  s.textContent = label;
  b.textContent = value + " ";
  sm.textContent = unit;
  b.append(sm);
  e.textContent = note;
  a.append(s, b, e);
  return a;
}
function renderMetrics() {
  const m = result.metrics,
    box = $("metrics");
  box.replaceChildren();
  const fmt = (v, d = 3) => (v == null ? "—" : v.toFixed(d));
  const legacy = m.captured_wire_bytes != null;
  box.append(
    metric(
      "TỔNG THỜI GIAN",
      fmt(m.total_ms, 2),
      "ms",
      "gồm tạo khóa và chứng chỉ",
    ),
    metric(
      "MÃ HÓA",
      fmt(m.encrypt_ms),
      "ms",
      m.encrypt_ms == null ? "không tách được" : result.config.cipher,
    ),
    metric(
      legacy ? "KẾT NỐI VÀ TẢI" : "TRUYỀN TCP",
      fmt(legacy ? m.end_to_end_ms : m.tcp_loopback_ms),
      "ms",
      legacy ? "bao gồm handshake và HTTP" : "truyền dữ liệu",
    ),
    metric(
      legacy ? "BYTE TOÀN PHIÊN" : "DỮ LIỆU TRUYỀN",
      legacy ? m.captured_wire_bytes : m.frame_bytes,
      "byte",
      legacy
        ? "gồm handshake và HTTP"
        : `bản rõ ${m.plaintext_bytes} byte · phụ trội ${m.wire_overhead_bytes} byte`,
    ),
  );
  $("metrics-more").textContent =
    `Xác thực & giải mã: ${fmt(m.decrypt_verify_ms)} ms   ·   CPU tiến trình: ${fmt(m.process_cpu_ms)} ms   ·   Tag: ${m.tag_bytes ?? "—"} byte   ·   ${result.mode === "real" ? `Handshake: ${fmt(m.handshake_ms)} ms / ${m.handshake_bytes ?? "—"} byte` : `Thiết lập mô hình: ${fmt(m.setup_ms)} ms`}`;
}
function renderSteps() {
  const box = $("steps");
  box.replaceChildren();
  $("step-count").textContent = `${result.steps.length} BƯỚC`;
  result.steps.forEach((s, i) => {
    const button = document.createElement("button"),
      n = document.createElement("span"),
      text = document.createElement("span"),
      title = document.createElement("b"),
      actor = document.createElement("small"),
      ms = document.createElement("span");
    button.className = "step" + (i === selected ? " active" : "");
    n.className = "step-num";
    n.textContent = String(i + 1).padStart(2, "0");
    text.className = "step-text";
    title.textContent = s.title;
    actor.textContent = s.actor;
    ms.className = "step-time";
    ms.textContent =
      s.duration_ms == null ? "—" : s.duration_ms.toFixed(3) + " ms";
    text.append(title, actor);
    button.append(n, text, ms);
    button.onclick = () => {
      selected = i;
      renderSteps();
      renderDetail();
    };
    box.append(button);
  });
}
function renderDetail() {
  const s = result.steps[selected],
    box = $("detail");
  box.replaceChildren();
  const head = document.createElement("div"),
    title = document.createElement("h3"),
    time = document.createElement("small"),
    desc = document.createElement("p");
  head.className = "detail-heading";
  title.textContent = s.title;
  time.textContent =
    s.duration_ms == null
      ? "Thời gian riêng: không có"
      : s.duration_ms.toFixed(3) + " ms";
  head.append(title, time);
  desc.className = "detail-desc";
  desc.textContent = s.description || descriptions[selected] || "";
  box.append(head, desc);
  if (s.method) {
    const method = document.createElement("p"),
      label = document.createElement("b");
    label.textContent = "Hàm / cách xử lý: ";
    method.append(label, document.createTextNode(s.method));
    box.append(method);
  }
  if (s.context) {
    const context = document.createElement("div");
    context.className = "step-context";
    for (const [label, value] of [
      ["Vai trò", s.context.roles],
      ["Nơi lưu khóa", s.context.storage],
      ["Phạm vi", s.context.scope],
    ]) {
      const p = document.createElement("p"),
        b = document.createElement("b");
      b.textContent = label + ": ";
      p.append(b, document.createTextNode(value));
      context.append(p);
    }
    box.append(context);
  }
  const addRows = (container, values, explanations) => {
    for (const [key, value] of Object.entries(values || {})) {
      const row = document.createElement("div"),
        label = document.createElement("div"),
        data = document.createElement("div");
      row.className = "data-row";
      label.className = "data-key";
      data.className = "data-value";
      label.textContent = names[key] || key;
      data.textContent =
        value === null
          ? "Không có hoặc không quan sát được"
          : typeof value === "boolean"
            ? value
              ? "Có"
              : "Không"
            : typeof value === "object"
              ? JSON.stringify(value, null, 2)
              : String(value);
      row.append(label, data);
      const explanation = explanations?.[key];
      if (explanation) {
        const info = document.createElement("div");
        info.className = "value-explanation";
        for (const [caption, text] of [
          ["Nằm ở đâu", explanation.location],
          ["Sinh ra / lấy từ", explanation.origin],
          ["Ý nghĩa / dùng để", explanation.purpose],
        ]) {
          const p = document.createElement("p"),
            b = document.createElement("b");
          b.textContent = caption + ": ";
          p.append(b, document.createTextNode(text));
          info.append(p);
        }
        row.append(info);
      }
      container.append(row);
    }
  };
  const group = (heading, values, kind) => {
    const section = document.createElement("section"),
      label = document.createElement("div"),
      badge = document.createElement("span");
    section.className = "io-group io-" + kind;
    label.className = "io-heading";
    badge.className = "io-icon";
    badge.textContent = kind === "input" ? "↓" : "↑";
    label.append(badge, document.createTextNode(heading));
    section.append(label);
    addRows(
      section,
      values,
      s.explanations?.[kind === "input" ? "inputs" : "outputs"],
    );
    return section;
  };
  box.append(
    group("Tham số đầu vào", s.inputs, "input"),
    group("Kết quả đầu ra", s.outputs, "output"),
  );
  for (const operation of s.operations || []) {
    const section = document.createElement("section"),
      heading = document.createElement("h4"),
      method = document.createElement("p");
    section.className = "io-group";
    heading.textContent = operation.title;
    method.textContent = operation.method;
    section.append(heading, method);
    for (const [label, values] of [
      ["Đầu vào", operation.inputs],
      ["Đầu ra", operation.outputs],
    ]) {
      const subheading = document.createElement("b");
      subheading.textContent = label;
      section.append(subheading);
      addRows(section, values);
    }
    box.append(section);
  }
  const raw = document.createElement("details"),
    summary = document.createElement("summary");
  raw.className = "raw-details";
  summary.textContent = "Xem thông tin gốc của bước";
  raw.append(summary);
  addRows(raw, s.details);
  box.append(raw);
}
async function run() {
  const text = $("message").value;
  if (!text.trim()) {
    $("status").textContent = "Hãy nhập thông điệp.";
    return;
  }
  $("run").disabled = true;
  $("run").textContent = "Đang thực hiện…";
  $("status").textContent = "Đang tạo khóa và chạy các bước…";
  try {
    const request = {
      mode: $("mode").value,
      message: text,
      config: {
        version: $("version").value,
        exchange: $("exchange").value,
        authentication: $("authentication").value,
        cipher: $("cipher").value,
        hash_name: $("hash").value,
        rsa_bits: Number($("rsa_bits").value),
      },
      tamper: $("tamper").checked,
    };
    const response = await fetch("/api/message", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Lab-Token": window.LAB_TOKEN,
      },
      body: JSON.stringify(request),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Không chạy được");
    result = data;
    selected = 0;
    renderMetrics();
    renderSteps();
    renderDetail();
    $("export").disabled = false;
    const evidence =
      data.steps.find((s) => s.details.observed_protocol) ||
      data.steps.find((s) => s.details.certificate_verified);
    const observed = evidence
      ? (evidence.details.observed_protocol || evidence.details.version) +
        " / " +
        (evidence.details.suite || evidence.details.cipher) +
        (evidence.details.observed_group
          ? " / " + evidence.details.observed_group
          : "") +
        (evidence.details.authentication
          ? " / " + evidence.details.authentication
          : "")
      : "thuật toán theo cấu hình mô hình";
    $("run-summary").textContent =
      (data.mode === "real" ? "KẾT NỐI THỰC" : "MÔ HÌNH") +
      "  ·  " +
      observed +
      "  ·  " +
      data.model;
    const badge = $("result-badge");
    badge.className = "badge " + (data.status === "success" ? "ok" : "bad");
    badge.textContent =
      data.status === "success" ? "✓  B NHẬN THÀNH CÔNG" : "×  B TỪ CHỐI";
    $("status").textContent = "Hoàn thành · Chọn một bước để xem dữ liệu";
  } catch (e) {
    $("status").textContent = "Lỗi: " + e.message;
    $("status").className = "status-error";
  } finally {
    $("run").disabled = $("version").value === "SSL 1.0";
    $("run").innerHTML = buttonLabel() + " <span>→</span>";
  }
}
$("run").addEventListener("click", run);
$("export").addEventListener("click", () => {
  if (!result) return;
  const blob = new Blob([JSON.stringify(result, null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "crypto-lab-message.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
$("message").dispatchEvent(new Event("input"));
updateChoices("init");
run();
