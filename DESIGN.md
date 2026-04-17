# Design Document — Security Dashboard

This document describes the **user interface** and **UX** of the phishing detection web front end (`templates/index.html`).

---

## Goals

- **Clarity:** One primary action — paste a URL and analyze it.
- **Trust:** Show **why** the model flagged a URL (technical details / top features).
- **Feedback:** Clear loading state while the backend runs inference.
- **Risk communication:** Color-coded verdict aligned with security mental models (green = safe, amber = caution, red = danger).

---

## Visual theme

- **Dark background** (`slate-950` / `slate-900`) to read as a “security operations” style console.
- **Accent:** Cyan for primary actions and loading (Analyze button, scanning indicator).
- **Typography:** Large readable headings; monospace-friendly numeric display for probability.

---

## Layout structure

1. **Header** — Product title (“Security Dashboard”) and one-line subtitle describing ML-powered analysis.
2. **Input card** — URL text field + **Analyze** button; optional loading row (“Scanning...”) with spinner.
3. **Results card** (shown after success) — Two columns on wide screens:
   - **Verdict** (Safe / Suspicious / Malicious) with color styling.
   - **Malicious probability** as a **horizontal progress bar** (0–100% width), with numeric probability beside it.
4. **Technical Details** — List of **top_features** from the API (feature name, value, influence score) so judges see transparency.

---

## Interaction flow

```text
User enters URL → clicks Analyze
    → Button disabled, “Scanning...” visible
    → fetch POST /predict { url }
    → Parse JSON
    → Show result card, set bar width = probability * 100
    → Render top_features list
    → Re-enable button, hide loading
```

---

## Color mapping (verdict)

| Verdict | Meaning (UI) | Tailwind-style intent |
|---------|----------------|------------------------|
| Safe | Low malicious probability | Green |
| Suspicious | Medium risk | Amber |
| Malicious | High risk | Red |

The same palette is applied to the **verdict text** and the **probability bar** for consistency.

---

## Accessibility & polish

- **Disabled state** on the button during request to prevent double submits.
- **Error handling:** User-facing alert on network or API errors.
- **Responsive:** Stacks vertically on small screens; bar and verdict remain readable.

---

## Dependencies (front end only)

- **Tailwind CSS** via CDN (`cdn.tailwindcss.com`) — no local build step required for demos.
- **Vanilla JavaScript** — no React/Vue; easy for judges to read.

---

## Future UI enhancements (optional)

- Replace alerts with inline error banners.
- Add example URLs or a “paste from clipboard” shortcut.
- Optional dark/light toggle if brand guidelines require it.
