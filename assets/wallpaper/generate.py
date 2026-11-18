import sys
W, H = 3840, 2160
C = W // 2
# Usage: python3 generate.py out.svg   (render to PNG with any browser or rsvg-convert)

glyphs = {
 'H': ["██   ██","██   ██","███████","██   ██","██   ██"],
 'E': ["███████","██     ","█████  ","██     ","███████"],
 'L': ["██     ","██     ","██     ","██     ","███████"],
 'O': ["███████","██   ██","██   ██","██   ██","███████"],
 'U': ["██   ██","██   ██","██   ██","██   ██","███████"],
 'N': ["██   ██","███  ██","██ █ ██","██  ███","██   ██"],
 'D': ["██████ ","██   ██","██   ██","██   ██","██████ "],
}
word = "HELLHOUND"
cw, ch = 26, 52                     # one terminal cell
cols = len(word) * 7 + (len(word) - 1) * 2
lx0 = C - cols * cw // 2
ly0 = 1190

out = []
a = out.append
a(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">')
a('''<defs>
 <radialGradient id="bg" cx="50%" cy="42%" r="75%">
  <stop offset="0" stop-color="#1a0707"/><stop offset=".45" stop-color="#0c0507"/><stop offset="1" stop-color="#030304"/>
 </radialGradient>
 <radialGradient id="glow" cx="50%" cy="50%" r="50%">
  <stop offset="0" stop-color="#ff3b1f" stop-opacity=".38"/><stop offset=".5" stop-color="#b3150b" stop-opacity=".12"/><stop offset="1" stop-color="#000" stop-opacity="0"/>
 </radialGradient>
 <linearGradient id="logo" x1="0" y1="0" x2="1" y2="1">
  <stop offset="0" stop-color="#ff2a1a"/><stop offset=".55" stop-color="#ff5a1f"/><stop offset="1" stop-color="#ff9a2e"/>
 </linearGradient>
 <linearGradient id="eye" x1="0" y1="0" x2="1" y2="0">
  <stop offset="0" stop-color="#ffd27a"/><stop offset="1" stop-color="#ff5a12"/>
 </linearGradient>
 <filter id="soft" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="18"/></filter>
 <filter id="eyeglow" x="-200%" y="-200%" width="500%" height="500%"><feGaussianBlur stdDeviation="14" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
 <pattern id="grid" width="96" height="96" patternUnits="userSpaceOnUse"><path d="M96 0H0V96" fill="none" stroke="#ff3b1f" stroke-opacity=".045" stroke-width="2"/></pattern>
 <pattern id="scan" width="6" height="6" patternUnits="userSpaceOnUse"><rect width="6" height="3" fill="#000" fill-opacity=".22"/></pattern>
 <radialGradient id="vig" cx="50%" cy="50%" r="72%"><stop offset=".6" stop-color="#000" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity=".85"/></radialGradient>
</defs>''')
a(f'<rect width="{W}" height="{H}" fill="url(#bg)"/>')
a(f'<rect width="{W}" height="{H}" fill="url(#grid)"/>')

# faint scan-log columns at the sides (decorative example lines)
logL = ["▶ calibrating + scanning /", "[200] /admin            page, 4 KB", "[301] /backup           directory",
        "[403] /.git/config      forbidden", "[200] /api/v1/users     JSON endpoint", "[500] /api/export       server error",
        "[302] /dashboard        login wall", "[200] /swagger.json     text file", "✓ crawl done in 2.4s", "[200] /metrics          text file",
        "[301] /staging          directory", "[401] /internal         protected", "! firewall slowed scan to 4 req/s",
        "[200] /robots.txt       text file", "[200] /sitemap.xml      XML document", "▶ running Tier-A security checks"]
logR = ["[HIGH  ] sensitive-file  /.env", "[HIGH  ] sensitive-file  /.git/config", "[MEDIUM] dir-listing     /ftp/",
        "[MEDIUM] exposed-copy    /test/", "[MEDIUM] sensitive-file  /metrics", "[LOW   ] upload-form     /profile",
        "[LOW   ] methods         /api", "[INFO  ] server header   nginx", "[openapi] 42 routes declared",
        "[graphql] introspection enabled", "[forms] 3 form(s) found", "[crawl] 128 linked page(s)",
        "✓ security checks done in 1.6s", "hellhound: 37 findings in 12 clusters", "▶ probing OpenAPI/GraphQL", "✓ wrote SARIF report"]
def col(line):
    for k, c in (("[2", "#3ddc84"), ("[3", "#3fc5d6"), ("[40", "#f5c542"), ("[5", "#ff4d4d"), ("[HIGH", "#ff4d4d"),
                 ("[MEDIUM", "#ff8a2a"), ("[LOW", "#f5c542"), ("[INFO", "#8a8a96"), ("✓", "#3ddc84"), ("!", "#f5c542"), ("▶", "#6aa8ff")):
        if line.startswith(k):
            return c
    return "#c9c9d1"
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
for x, lines, anchor in ((150, logL, "start"), (W - 150, logR, "end")):
    for i, ln in enumerate(lines):
        y = 300 + i * 104
        a(f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-family="DejaVu Sans Mono, Noto Sans Mono, monospace" font-size="30" xml:space="preserve" fill="{col(ln)}" fill-opacity=".17">{esc(ln)}</text>')

# glow behind head and logo
a('<g transform="translate(0,120)">')
a(f'<ellipse cx="{C}" cy="760" rx="820" ry="560" fill="url(#glow)"/>')
a(f'<ellipse cx="{C}" cy="{ly0+130}" rx="1250" ry="260" fill="url(#glow)"/>')

# low-poly hound head (left half mirrored); points are (dx, y)
c0, c1, c2, c3, c4 = "#160505", "#2a0909", "#430d0d", "#5e1212", "#7d1616"
facets = [
 ([(-200,300),(-275,565),(-90,470)], c3),            # ear outer
 ([(-198,372),(-238,538),(-116,482)], c0),           # ear inner
 ([(-90,470),(0,440),(0,620),(-150,600)], c2),       # forehead
 ([(-90,470),(-150,600),(-275,565)], c4),            # brow
 ([(-275,565),(-150,600),(-335,725)], c1),           # temple
 ([(-335,725),(-150,600),(-122,762)], c2),           # upper cheek
 ([(-335,725),(-122,762),(-262,905)], c1),           # lower cheek
 ([(-150,600),(0,620),(-52,802),(-122,762)], c3),    # snout bridge
 ([(0,620),(0,940),(-52,802)], c4),                  # bridge centre
 ([(-122,762),(-52,802),(-62,962),(-162,922)], c2),  # muzzle
 ([(-52,802),(0,940),(-62,962)], c3),                # muzzle top
 ([(-262,905),(-122,762),(-162,922)], c0),           # jaw shadow
 ([(-262,905),(-162,922),(-62,962),(0,1062),(-150,1032)], c1),  # lower jaw
]
def poly(pts, fill, mirror):
    s = " ".join(f"{C + (-dx if mirror else dx)},{y}" for dx, y in pts)
    return f'<polygon points="{s}" fill="{fill}" stroke="#ff4a1f" stroke-opacity=".28" stroke-width="2.5" stroke-linejoin="round"/>'
# right half drawn a shade darker for depth
darker = {c0: "#100303", c1: "#200707", c2: "#350a0a", c3: "#4a0e0e", c4: "#621111"}
for pts, f in facets:
    a(poly(pts, f, False))
    a(poly(pts, darker[f], True))
# nose
a(f'<polygon points="{C-58},930 {C+58},930 {C+32},990 {C-32},990" fill="#050101" stroke="#ff4a1f" stroke-opacity=".35" stroke-width="2.5"/>')
a(f'<polygon points="{C-40},938 {C},934 {C-10},955" fill="#ffffff" fill-opacity=".10"/>')
# eyes
for m in (1, -1):
    pts = [(-212,650),(-118,636),(-98,676),(-178,690)]
    s = " ".join(f"{C + dx*m},{y}" for dx, y in pts)
    a(f'<polygon points="{s}" fill="url(#eye)" filter="url(#eyeglow)"/>')
    a(f'<polygon points="{s}" fill="#fff4d6" fill-opacity=".35" transform="translate(0,-2)"/>')

# block logo, same glyph grid as the terminal banner
blocks = []
for li, chg in enumerate(word):
    g = glyphs[chg]
    for r in range(5):
        for k, cell in enumerate(g[r]):
            if cell == "█":
                x = lx0 + (li * 9 + k) * cw
                y = ly0 + r * ch
                blocks.append(f'<rect x="{x}" y="{y}" width="{cw-3}" height="{ch-4}" rx="2"/>')
a(f'<g fill="#ff2a1a" opacity=".55" filter="url(#soft)">' + "".join(blocks) + '</g>')
a(f'<g fill="url(#logo)">' + "".join(blocks) + '</g>')
a(f'<g fill="#ffffff" fill-opacity=".07">' + "".join(b.replace(f'height="{ch-4}"', f'height="{(ch-4)//3}"') for b in blocks) + '</g>')

ty = ly0 + 5 * ch + 130
a(f'<text x="{C}" y="{ty}" text-anchor="middle" font-family="DejaVu Sans Mono, Noto Sans Mono, monospace" font-size="46" letter-spacing="14" fill="#e9e3df" fill-opacity=".82">CALIBRATED RECON THAT CLASSIFIES WHAT IT FINDS</text>')
a(f'<rect x="{C-360}" y="{ty+58}" width="720" height="3" fill="#ff4a1f" fill-opacity=".55"/>')
a(f'<text x="{C}" y="{ty+140}" text-anchor="middle" font-family="DejaVu Sans Mono, Noto Sans Mono, monospace" font-size="34" letter-spacing="6" fill="#ff7a3a" fill-opacity=".85">calibrate  ·  crawl  ·  fuzz  ·  classify</text>')
a('</g>')
a(f'<text x="{C}" y="{H-90}" text-anchor="middle" font-family="DejaVu Sans Mono, Noto Sans Mono, monospace" font-size="30" letter-spacing="4" fill="#9a9aa6" fill-opacity=".55">hellhound  ·  authorized security testing only</text>')

a(f'<rect width="{W}" height="{H}" fill="url(#scan)" opacity=".5"/>')
a(f'<rect width="{W}" height="{H}" fill="url(#vig)"/>')
a('</svg>')
open(sys.argv[1], "w").write("\n".join(out))
