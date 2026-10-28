// Live GPU catalog for /rent/: reads the public catalog JSON that Common Foundry's directory server publishes and
// draws one card per listed machine. No wallet, no keys, nothing private: the file holds only what hosts sign.
(function () {
  "use strict";
  var CATALOG_URL = "https://sg-rpc.commonfoundry.ai/stats/marketplace.json";
  var REFRESH_MS = 60000;
  var cards = document.getElementById("cards");
  var empty = document.getElementById("empty");
  var status = document.getElementById("status");

  function text(tag, className, value) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined && value !== null) node.textContent = String(value);
    return node;
  }
  function spec(dl, label, value) {
    var wrap = document.createElement("div");
    wrap.appendChild(text("dt", null, label));
    wrap.appendChild(text("dd", null, value));
    dl.appendChild(wrap);
  }
  function gib(mib) { return (mib / 1024).toFixed(mib % 1024 ? 1 : 0) + " GiB"; }
  function hours(seconds) {
    var h = Math.round(Number(seconds) / 3600);
    return h >= 24 && h % 24 === 0 ? (h / 24) + (h === 24 ? " day" : " days") : h + " h";
  }
  function price(host) {
    var cmfd = Number(host.price_cmfd_per_hour);
    return (cmfd >= 10 ? cmfd.toFixed(1) : cmfd.toFixed(2)) + " CMFD";
  }
  var VERIFICATION = {
    passed: ["ok", "Tested"],
    not_tested: ["idle", "Not tested yet"],
    failed: ["no", "Failed its last test"],
    different_hardware: ["no", "Hardware changed since test"]
  };

  function card(host) {
    var li = text("li", "card");
    var gpu = host.gpus && host.gpus[0];
    var top = text("div", "card-top");
    var title = text("h3", "gpu", gpu ? gpu.model.replace(/^NVIDIA /, "") : "GPU");
    var sub = [];
    if (gpu) sub.push(gib(gpu.vram_mib) + " VRAM");
    if (host.gpus && host.gpus.length > 1) sub.push(host.gpus.length + " GPUs");
    if (gpu && gpu.pcie) sub.push("PCIe " + gpu.pcie.generation + ".0 x" + gpu.pcie.width);
    title.appendChild(text("small", null, sub.join(" · ")));
    top.appendChild(title);
    var p = text("div", "price");
    p.appendChild(text("b", null, price(host)));
    p.appendChild(text("small", null, "per hour"));
    if (host.price_usd_per_hour !== undefined) p.appendChild(text("span", "usd", "≈ $" + Number(host.price_usd_per_hour).toFixed(2)));
    top.appendChild(p);
    li.appendChild(top);

    var dl = text("dl", "specs");
    var cpu = host.cpu_cores + " cores" + (host.cpu_threads ? " / " + host.cpu_threads + " threads" : "");
    if (host.cpu_model) spec(dl, "CPU", host.cpu_model.replace(/ with Radeon Graphics$/, "") + " · " + cpu);
    else spec(dl, "CPU", cpu);
    spec(dl, "RAM", gib(host.ram_mib));
    spec(dl, "Disk", host.disk_gib + " GiB");
    spec(dl, "Network", host.download_mbps + " ↓ / " + host.upload_mbps + " ↑ Mbit/s");
    spec(dl, "Driver", host.driver_version + " · CUDA " + host.cuda_version);
    spec(dl, "Max rental", hours(host.max_rental_seconds));
    li.appendChild(dl);

    var foot = text("div", "card-foot");
    var v = VERIFICATION[host.verification] || ["idle", host.verification];
    foot.appendChild(text("span", "pill " + v[0], v[1]));
    foot.appendChild(text("span", null, (host.region || "") + (host.traffic_price_per_gb_atoms === "0" ? " · no traffic charge" : "")));
    li.appendChild(foot);
    return li;
  }

  function render(data) {
    var hosts = (data && data.hosts) || [];
    cards.textContent = "";
    hosts.forEach(function (host) { cards.appendChild(card(host)); });
    empty.hidden = hosts.length > 0;
    var when = new Date(data.observed_unix * 1000);
    var age = Math.round((Date.now() - when.getTime()) / 60000);
    status.textContent = hosts.length + (hosts.length === 1 ? " machine" : " machines") + " · height " + data.checked_height +
      " · " + (age <= 1 ? "updated just now" : "updated " + age + " min ago");
    status.classList.toggle("stale", age > 10);
  }

  function load() {
    fetch(CATALOG_URL, { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(render)
      .catch(function () {
        status.textContent = "The live list is not reachable right now; the renter app shows the same machines.";
        status.classList.add("stale");
        if (!cards.children.length) empty.hidden = false;
      });
  }
  load();
  setInterval(load, REFRESH_MS);
})();
