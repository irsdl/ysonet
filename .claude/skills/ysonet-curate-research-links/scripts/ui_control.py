#!/usr/bin/env python3
"""Look at (and drive) a window on Windows, with no third-party packages.

Built for the link sweep: when a page answers with a wall, the only way to know
what is actually on screen - a spinner, a checkbox, a cookie banner, or the
article itself - is to look at it. Everything here is ctypes over Win32, so it
works on a stock Python with nothing installed.

    python ui_control.py windows                       list visible top windows
    python ui_control.py windows --match edge          only titles containing "edge"
    python ui_control.py shot --out shot.png           whole screen
    python ui_control.py shot --match "Medium" --out m.png    just that window
    python ui_control.py shot --match Edge --raise --out m.png  bring it up first

The PNG is written with zlib alone, so an agent can read the image back and see
the page. Keep captures out of the repository: they are screenshots of whatever
was on the maintainer's screen.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
import zlib

if sys.platform != "win32":
    print("ui_control.py is Windows only.")
    sys.exit(2)

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0
SW_RESTORE = 9


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wt.DWORD), ("biWidth", ctypes.c_long), ("biHeight", ctypes.c_long),
        ("biPlanes", wt.WORD), ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
        ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wt.DWORD),
        ("biClrImportant", wt.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


def list_windows(match: str = ""):
    """Visible top level windows with a title, as (hwnd, title, rect)."""
    found = []
    EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def cb(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        if not n:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, buf, n + 1)
        title = buf.value
        if match and match.lower() not in title.lower():
            return True
        rect = wt.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        if rect.right - rect.left < 40 or rect.bottom - rect.top < 40:
            return True
        found.append((hwnd, title, (rect.left, rect.top, rect.right, rect.bottom)))
        return True

    user32.EnumWindows(EnumProc(cb), 0)
    return found


def write_png(path: str, width: int, height: int, rgb: bytes) -> None:
    """Minimal PNG writer: filter 0 per row, one IDAT, stdlib zlib only."""
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)
        raw += rgb[y * stride:(y + 1) * stride]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
           + chunk(b"IDAT", zlib.compress(bytes(raw), 6)) + chunk(b"IEND", b""))
    with open(path, "wb") as fh:
        fh.write(png)


def capture(left: int, top: int, width: int, height: int, path: str, scale: int = 1) -> str:
    """BitBlt a screen rectangle and write it as a PNG. scale=2 halves each side."""
    screen_dc = user32.GetDC(0)
    mem_dc = gdi32.CreateCompatibleDC(screen_dc)
    bitmap = gdi32.CreateCompatibleBitmap(screen_dc, width, height)
    gdi32.SelectObject(mem_dc, bitmap)
    if not gdi32.BitBlt(mem_dc, 0, 0, width, height, screen_dc, left, top, SRCCOPY):
        raise OSError("BitBlt failed (error %d)" % ctypes.get_last_error())

    info = BITMAPINFO()
    info.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    info.bmiHeader.biWidth = width
    info.bmiHeader.biHeight = -height          # negative: top-down rows
    info.bmiHeader.biPlanes = 1
    info.bmiHeader.biBitCount = 32
    info.bmiHeader.biCompression = 0
    buf = ctypes.create_string_buffer(width * height * 4)
    got = gdi32.GetDIBits(mem_dc, bitmap, 0, height, buf, ctypes.byref(info), DIB_RGB_COLORS)
    gdi32.DeleteObject(bitmap)
    gdi32.DeleteDC(mem_dc)
    user32.ReleaseDC(0, screen_dc)
    if not got:
        raise OSError("GetDIBits failed (error %d)" % ctypes.get_last_error())

    src = buf.raw
    if scale < 1:
        scale = 1
    out_w, out_h = width // scale, height // scale
    rgb = bytearray(out_w * out_h * 3)
    i = 0
    for y in range(out_h):
        row = (y * scale) * width * 4
        for x in range(out_w):
            p = row + (x * scale) * 4
            rgb[i] = src[p + 2]        # BGRA on the wire, RGB in the file
            rgb[i + 1] = src[p + 1]
            rgb[i + 2] = src[p]
            i += 3
    write_png(path, out_w, out_h, bytes(rgb))
    return "%s (%dx%d)" % (path, out_w, out_h)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    lw = sub.add_parser("windows", help="list visible top level windows")
    lw.add_argument("--match", default="", help="only titles containing this text")

    sh = sub.add_parser("shot", help="save a PNG of the screen or one window")
    sh.add_argument("--match", default="", help="capture the first window whose title matches")
    sh.add_argument("--out", default="screenshot.png")
    sh.add_argument("--scale", type=int, default=1, help="2 halves each side, for a smaller file")
    sh.add_argument("--raise", dest="raise_it", action="store_true",
                    help="bring the matched window to the front first")

    args = p.parse_args()

    if args.cmd == "windows":
        rows = list_windows(args.match)
        if not rows:
            print("no visible window matched")
            return 1
        for hwnd, title, r in rows:
            print("%-10s %4d,%-4d %4dx%-4d  %s"
                  % (hwnd, r[0], r[1], r[2] - r[0], r[3] - r[1],
                     title.encode("ascii", "replace").decode("ascii")[:70]))
        return 0

    left = top = 0
    width = user32.GetSystemMetrics(0)
    height = user32.GetSystemMetrics(1)
    if args.match:
        rows = list_windows(args.match)
        if not rows:
            print("no visible window titled like %r" % args.match)
            return 1
        hwnd, title, r = rows[0]
        if args.raise_it:
            user32.ShowWindow(hwnd, SW_RESTORE)
            user32.SetForegroundWindow(hwnd)
            import time
            time.sleep(0.6)
            _h, _t, r = list_windows(args.match)[0]
        left, top = max(r[0], 0), max(r[1], 0)
        width, height = min(r[2], width) - left, min(r[3], height) - top
        print("window: %s" % title.encode("ascii", "replace").decode("ascii")[:70])
    if width < 1 or height < 1:
        print("nothing to capture (window is off screen or minimised)")
        return 1
    print("saved: %s" % capture(left, top, width, height, args.out, args.scale))
    return 0


if __name__ == "__main__":
    sys.exit(main())
