# eMAN — Your UI-Friendly eBPF Manager

**eMAN** is an intuitive, terminal-based interface for managing, exploring, and interacting with **eBPF programs**.
It takes the complexity of raw eBPF tooling and wraps it in a clean, user-friendly UI, making it easier for developers, SREs, and security engineers to understand, debug, and control eBPF workloads in real time.

---

## 📜 Description

eBPF (extended Berkeley Packet Filter) is a powerful kernel technology enabling deep observability, security enforcement, and networking capabilities without modifying the kernel itself. However, most eBPF tools are CLI-heavy, fragmented, and require intricate knowledge to operate effectively.

**eMAN** bridges that gap by:

* Providing a **visual, interactive dashboard** for eBPF programs, maps, and events.
* Offering **intuitive navigation** with tables, lists, and detailed info views.
* Making **eBPF management accessible** to both experts and newcomers.

---

## 💡 How It Can Help

* **For Observability Engineers** — Quickly inspect running eBPF programs, view map data, and track metrics visually.
* **For Security Teams** — Audit loaded eBPF probes and see their configuration in real time.
* **For Developers** — Speed up debugging of eBPF-based applications without memorizing complex CLI commands.
* **For SREs** — Monitor eBPF states in production without hopping between multiple tools.

By removing steep learning curves, **eMAN** can drastically reduce operational friction, enhance team adoption of eBPF, and improve both performance and security insights.

---

## 🚀 Features

* **Interactive TUI (Terminal User Interface)** powered by Rust.
* **Map list view** — See available eBPF maps with IDs, types, and max entries.
* **Map detail view** — Inspect map contents, configurations, and related programs.
* **Smooth navigation** — Scrollbars, keybindings, and clean layouts for quick access.
* **Header/Footer context bars** for relevant actions and information.
* **Multi-screen support** — Switch seamlessly between overviews and detail screens.
* **Modular UI components** — Easy to extend and customize.
* **Efficient rendering** — Built to handle large map lists without lag.

---

## 📦 Current Development

* Map listing and detail screens are functional.
* Scrollable tables and sections for smooth data browsing.
* Modular UI architecture (`uis::header`, `uis::table`, etc.).
* Core layout system using `ratatui` for consistent rendering.
* Initial state management for navigation and selection.

---

## 🛣 Future Development / Roadmap

1. **Program Management**

   * Load/unload eBPF programs from the UI.
   * Attach/detach hooks dynamically.

2. **Map Editing**

   * Modify eBPF map values directly from the UI.
   * Export/import maps as JSON or binary.

3. **Metrics & Live Updates**

   * Real-time counters, histograms, and tracing.
   * Integration with perf events.

4. **Security Auditing**

   * Show program origin, permissions, and verifier logs.
   * Highlight unsigned or suspicious programs.

5. **Plugin System**

   * Extend functionality with custom modules.
   * Support for tracing, networking, and security plugins.

6. **Remote Management**

   * Manage eBPF programs across nodes via SSH or gRPC.

7. **User Profiles**

   * Save preferred layouts, filters, and viewing modes.

---

## 📊 Impact

eBPF adoption is growing rapidly, but its ecosystem still struggles with approachability.
**eMAN** aims to:

* Shorten the learning curve for new users.
* Increase visibility of kernel-level operations.
* Empower teams to make informed decisions about eBPF usage.
* Reduce costly downtime by making debugging faster and more visual.

By making eBPF more accessible, **eMAN** helps unlock the full potential of modern observability and security without sacrificing performance.

---

## ⚙️ Installation & Usage (Coming Soon)

Once released, **eMAN** will be installable via Cargo:

Clone the repo and run from source:

```bash
git clone https://github.com/yourusername/eman.git
cd eman
sudo cargo run
```

## Screenshots

<img width="738" height="460" alt="image" src="https://github.com/user-attachments/assets/962290cb-d72f-4dfb-9a7a-9d9004c2bb7c" />
<img width="1907" height="1004" alt="image" src="https://github.com/user-attachments/assets/0b3f39bc-d115-42d9-901b-af7fd7e06590" />
<img width="1907" height="1004" alt="image" src="https://github.com/user-attachments/assets/0b564785-8c73-4c32-9058-5f3f5af37b97" />
<img width="1907" height="1004" alt="image" src="https://github.com/user-attachments/assets/694835b9-4616-428a-91d7-953d5eb4e7c8" />

---

## 🤝 Contributing

We welcome contributions in code, design, and documentation.
If you’d like to help shape **eMAN**, please open issues or pull requests.

---
