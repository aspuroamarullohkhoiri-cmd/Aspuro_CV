#!/usr/bin/env python3
"""Bangun dokumen aman untuk CV.
PDF -> JPG -> sensor data sensitif -> watermark -> enkripsi AES-256-GCM (.enc)

Pakai:  DOC_PASSWORD='kode-rahasia-anda' python3 build_docs.py
Butuh:  pip install pillow cryptography ; apt install poppler-utils tesseract-ocr
Taruh 3 PDF sumber di folder 'sumber/' (JANGAN di-commit ke GitHub).
Hasil di folder 'dokumen/' -> inilah yang di-commit.
"""
import os, re, json, subprocess, glob, tempfile, secrets, io
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SRC, OUT, DPI, ITER = 'sumber', 'dokumen', 130, 200_000
PWD = os.environ.get('DOC_PASSWORD') or exit('Set dulu: DOC_PASSWORD=...')
WM = 'Hanya untuk keperluan lamaran kerja - Aspuro A. Khoiri'
GROUPS = [  # (judul, file pdf, {halaman: rotasi derajat searah jarum jam})
    ('Ijazah & Transkrip', 'Aspuro_Ijazah_Pendidikan.pdf', {1: 90, 4: -90}),
    ('Sertifikat', 'Aspuro_Sertifikat.pdf', {}),
    ('Pengalaman Kerja', 'Aspuro_Pengalaman_Kerja.pdf', {}),
]
# Pola yang disensor (per file PDF). 'num' = token angka mengandung potongan ini,
# 'line' = seluruh baris alamat dari kata kunci hingga akhir baris.
RULES = {
    'Aspuro_Ijazah_Pendidikan.pdf': {'num': ['3216141', '6970003']},
    'Aspuro_Pengalaman_Kerja.pdf': {'num': ['3216141', '6970003', '2101549', '5494699', '2101002'],
                                    'line': ['Kobak', 'Sukamakmur', 'Sukakarya']},
}

def redact(img, rules, name):
    d = subprocess.run(['tesseract', '-', '-', '--psm', '11', 'tsv'], input=_jpg(img),
                       capture_output=True).stdout.decode(errors='ignore').splitlines()[1:]
    w = [dict(zip(('l', 'p', 'b', 'pa', 'li', 'wo', 'x', 'y', 'w', 'h', 'c', 't'), r.split('\t'))) for r in d]
    w = [x for x in w if len(x) == 12 and x['t'].strip()]
    dr, hit = ImageDraw.Draw(img), 0
    box = lambda x, y, ww, hh, p=5: dr.rectangle([x - p, y - p, x + ww + p, y + hh + p], fill='black')
    for x in w:
        if any(k in re.sub(r'\D', '', x['t']) or k in x['t'] for k in rules.get('num', [])) \
                and len(re.sub(r'\D', '', x['t'])) >= 6:
            box(*[int(x[k]) for k in 'xywh']); hit += 1
    for k in rules.get('line', []):
        for x in w:
            if k in x['t']:
                same = [z for z in w if abs(int(z['y']) - int(x['y'])) < 12]
                x0 = min(int(z['x']) for z in same if z['t'].startswith('Kp') or z['t'] == x['t'] or 'Kobak' in z['t'] or int(z['x']) >= int(x['x']) - 120)
                x0 = min(x0, int(x['x']))
                x1 = max(int(z['x']) + int(z['w']) for z in same)
                if x0 < img.width * 0.2: x0 = int(x['x'])
                box(x0, int(x['y']), x1 - x0, int(x['h'])); hit += 1
    print(f'  sensor {name}: {hit} area')
    return img

def _jpg(img):
    b = io.BytesIO(); img.save(b, 'JPEG', quality=92); return b.getvalue()

def watermark(img):
    ov = Image.new('RGBA', img.size, (0, 0, 0, 0)); f = ImageFont.load_default(size=max(14, img.width // 40))
    t = Image.new('RGBA', (img.width, 60), (0, 0, 0, 0))
    ImageDraw.Draw(t).text((0, 10), WM, font=f, fill=(90, 90, 90, 60))
    t = t.rotate(30, expand=True)
    for y in range(-t.height // 2, img.height, img.height // 3):
        for x in range(-100, img.width, img.width // 2): ov.alpha_composite(t, (max(x, 0), max(y, 0))) if x >= 0 and y >= 0 else None
    return Image.alpha_composite(img.convert('RGBA'), ov).convert('RGB')

def enc(data):
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    k = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(PWD.encode())
    return salt + iv + AESGCM(k).encrypt(iv, data, None)

os.makedirs(OUT, exist_ok=True)
for f in glob.glob(f'{OUT}/*'): os.remove(f)
manifest, n = [], 0
for title, pdf, rot in GROUPS:
    print(title)
    tmp = tempfile.mkdtemp()
    subprocess.run(['pdftoppm', '-jpeg', '-r', str(DPI), '-jpegopt', 'quality=88', f'{SRC}/{pdf}', f'{tmp}/p'], check=True)
    files = sorted(glob.glob(f'{tmp}/p-*.jpg'))
    items = []
    for i, p in enumerate(files, 1):
        img = Image.open(p).convert('RGB')
        if i in rot: img = img.rotate(-rot[i], expand=True)
        if pdf in RULES: img = redact(img, RULES[pdf], f'{pdf} hal.{i}')
        b = io.BytesIO(); watermark(img).save(b, 'JPEG', quality=84, optimize=True)
        n += 1; fn = f'd{n:02d}.enc'
        open(f'{OUT}/{fn}', 'wb').write(enc(b.getvalue()))
        items.append({'f': fn, 'n': f'{title} - hal {i}'})
    manifest.append({'g': title, 'items': items})
json.dump({'iter': ITER, 'groups': manifest}, open(f'{OUT}/manifest.json', 'w'), ensure_ascii=False)
print('selesai:', n, 'file terenkripsi di', OUT)
