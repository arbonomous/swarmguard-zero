# SwarmGuard brand

Quiet antivirus for AI agents — trustworthy, sharp, not a gamer/SOC toy.

**Product name:** SwarmGuard  
**Edition tagline:** ZERO — use sparingly (hackathon / submission titles only). Prefer **SwarmGuard** in UI.

## Motif

Shield + subtle swarm/nodes (network lattice). Not a cartoon bug, not an emoji. Simple enough to read at **16–22px** in the macOS menu bar.

## Color tokens

| Token | Hex | Use |
|-------|-----|-----|
| `signal` | `#3DD68C` | Primary / protected / positive |
| `ink` | `#0A0D12` | Page / chrome background |
| `surface` | `#121821` | Panels, secondary surfaces |
| `danger` | `#FF4D4D` | Threats, denials, errors |
| `text` | `#E8EDF5` | Primary copy |
| `muted` | `#8B95A8` | Captions, idle state |

Streamlit theme mirrors these in `.streamlit/config.toml`. Native popout uses the same tokens in `menubar.py`.

## Typography

- Prefer a geometric or humanist **sans** with character.
- Avoid defaulting brand samples to **Inter**, **Roboto**, or system Arial as the “logo font.”
- UI may use the host stack; wordmark art carries the brand type treatment.

## Assets (Muse Image)

Regenerate with Meta **muse-image-1.0**:

```bash
source .venv/bin/activate
python tools/generate_brand_muse.py
```

| File | Role |
|------|------|
| `swarmguard-mark.png` | Square mark (RGBA). Product icon, dashboard hero. |
| `swarmguard-icon-menu.png` | High-contrast menu-bar / panel header mark. |
| `swarmguard-icon-menu-template.png` | Black silhouette for AppKit template tinting. |
| `swarmguard-icon-menu-dark.png` | Packed light-on-ink preview (docs). |
| `swarmguard-popout-mock.png` | Muse Image UX target for the native Protector panel. |
| `swarmguard-wordmark.png` | Optional horizontal lockup (if present). |

## Usage

**Do**

- Lead with **SwarmGuard**; say “protector,” “gate,” “activity” — not “War Room.”
- Menu bar first; native popout is the everyday UI; Streamlit = advanced console.
- Keep menu-bar icon high contrast; template mode for macOS tinting.
- Use `signal` for healthy / enforcing; `danger` for deny / threat; `muted` for idle.

**Don’t**

- Purple gradients or “AI neon” purple/indigo themes.
- Neon glow overload or SOC-dashboard clutter.
- Emoji as the logo.
- Overuse **ZERO** in chrome.
- Call Muse Image at runtime for chrome — freeze reviewed assets.

## Continuity map

| Surface | Brand application |
|---------|-------------------|
| Menu bar (`menubar.py`) | Template/menu icon on `NSStatusItem`; name SwarmGuard |
| Native Protector panel | Ink panel, signal status, mark + title, denial list |
| Protector console (`dashboard.py`) | Mark + SwarmGuard title; theme tokens |
| Docs / demo video | Mark + popout mock as visual reference |

## Refresh menu bar icon

Quit via **Quit SwarmGuard menu**, then:

```bash
./run_menubar.sh
```

If a stale lock blocks relaunch: `rm /tmp/swarmguard-menubar.pid` (only when no menubar process is running).
