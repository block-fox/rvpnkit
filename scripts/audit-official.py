"""Read installed Qt translations/resources for an interoperability feature audit.

Writes local reference material only to ignored .local-audit/, never redistributes
the vendor binary, artwork, credentials or user configuration.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zlib

sys.stdout.reconfigure(encoding='utf-8')

ROOT = Path(__file__).resolve().parents[1]
INSTALL = Path(r"C:\Program Files (x86)\Radmin VPN")
OUT = ROOT / '.local-audit'
OUT.mkdir(exist_ok=True)

def qm_messages(path):
    data = path.read_bytes()
    position = 16
    result = []
    while position + 5 <= len(data):
        block = data[position]
        length = int.from_bytes(data[position + 1:position + 5], 'big')
        payload = data[position + 5:position + 5 + length]
        position += 5 + length
        if block != 0x69:
            continue
        index = 0
        message = {}
        while index < len(payload):
            tag = payload[index]
            index += 1
            if tag == 1:
                if message.get('source'):
                    result.append(message)
                message = {}
                continue
            if index + 4 > len(payload):
                break
            size = int.from_bytes(payload[index:index + 4], 'big')
            index += 4
            if size == 0xffffffff:
                continue
            value = payload[index:index + size]
            index += size
            if tag in (6, 7, 8):
                message[{6:'source', 7:'context', 8:'comment'}[tag]] = value.decode('utf-8', 'replace')
            elif tag == 3:
                message['translation'] = value.decode('utf-16-be', 'replace')
    return result

messages = qm_messages(INSTALL / 'RvRvpnGui_zh_CN.qm')
(OUT / 'translations.json').write_text(json.dumps(messages, ensure_ascii=False, indent=2), encoding='utf-8')
data = (INSTALL / 'RvRvpnGui.exe').read_bytes()
resources = []
for match in re.finditer(rb'\x78[\x01\x9c\xda]', data):
    offset = match.start()
    if offset < 4:
        continue
    expected = struct.unpack_from('>I', data, offset - 4)[0]
    if not 30 <= expected <= 3_000_000:
        continue
    try:
        decoder = zlib.decompressobj()
        content = decoder.decompress(data[offset:offset+3_000_000], 3_000_001)
    except zlib.error:
        continue
    if len(content) != expected or not decoder.eof:
        continue
    if b'import Qt' in content or b'qsTr(' in content:
        name = f'resource-{offset:08x}.qml'
        (OUT / name).write_bytes(content)
        resources.append({'file': name, 'bytes': len(content)})
(OUT / 'inventory.json').write_text(json.dumps({'sha256':hashlib.sha256(data).hexdigest(), 'translations':len(messages), 'qml':resources}, indent=2), encoding='utf-8')
print(f'Official audit: {len(messages)} translated messages, {len(resources)} local QML references.')
for message in messages:
    source = message['source'].replace('\n', ' ')[:180]
    print(f"{message.get('context', '')}: {source} => {message.get('translation', '')[:160]}")
