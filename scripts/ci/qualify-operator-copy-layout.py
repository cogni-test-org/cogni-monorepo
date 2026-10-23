#!/usr/bin/env python3
"""TEST-only seven-COPY qualification. No registry publication or runtime authority.

Fixed current fixture BASE; exact owned CI PR only. CLI and output contract lives
here rather than shared scripts/ci/AGENTS.md. Unknown metadata/identity is RED.
Whole-Q cost is diagnostic, never a normal performance sample.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
from urllib.parse import urlsplit, parse_qsl, unquote
import subprocess
import sys
import tarfile
import tempfile
import time

BASE = 'b4049ffab2cd6a04f3db48d1563bbc2edf37ed63'
RECIPE = 'nodes/operator/app/Dockerfile'
MAX_BYTES = 4 * 1024**3
MAX_MEMBERS = 500_000
PAX = {'path', 'linkpath', 'size', 'uid', 'gid', 'uname', 'gname', 'mtime', 'atime', 'ctime'}
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify_digest(data, digest):
    require(DIGEST.fullmatch(digest) and 'sha256:' + hashlib.sha256(data).hexdigest() == digest, 'digest mismatch')


def base_recipe(root):
    return subprocess.check_output(['git', '-C', str(root), 'show', f'{BASE}:{RECIPE}'], text=True)


def relocate(old):
    start = old.index('# Migrate runner — bundled into runtime image')
    end = old.index('\nEXPOSE 3000', start)
    block = old[start:end]
    require(block.count('\nCOPY --from=builder --chown=nextjs:nodejs ') == 7, 'expected exactly seven copies')
    require(not any('$' in line for line in block.splitlines() if line.startswith('COPY')), 'dynamic copy argument')
    remaining = old[:start] + old[end:]
    at = remaining.index('# Build SHA plumbing:')
    return remaining[:at] + block + '\n\n' + remaining[at:]


def assert_recipe(old, new):
    require(new == relocate(old), 'recipe differs beyond literal seven-copy relocation')
    after = new.split('ARG BUILD_SHA', 1)[1]
    require('COPY --from=builder' not in after, 'copy remains after SHA arg')
    block = old[old.index('# Migrate runner —'):old.index('\nEXPOSE 3000')]
    for line in block.splitlines():
        if line.startswith('COPY '):
            dest = line.split()[-1]
            require(dest.startswith('/app/') and '__cogni-build' not in dest and '/public' not in dest, 'copy overlaps SHA marker')


def safe_name(name):
    require(name and '\x00' not in name and not name.startswith('/'), 'unsafe path')
    parts = PurePosixPath(name).parts
    require('..' not in parts, 'traversal path')
    return str(PurePosixPath(name))


def _stream(value):
    return io.BytesIO(value) if isinstance(value, bytes) else value


def _pax(data):
    found = {}
    while data:
        length, sep, rest = data.partition(b' ')
        require(sep and length.isdigit(), 'malformed PAX length')
        size = int(length)
        require(0 < size <= len(data) and data[size-1:size] == b'\n', 'malformed PAX record')
        record = data[len(length)+1:size-1]
        key, sep, value = record.partition(b'=')
        require(sep, 'malformed PAX pair')
        key = key.decode('ascii')
        require(key in PAX and key not in found, 'unsupported or duplicate PAX attribute')
        text = value.decode('utf-8')
        require('\x00' not in text, 'NUL in PAX value')
        if key in ['uid', 'gid', 'size']:
            require(bool(re.fullmatch(r'[0-9]+', text)), 'invalid numeric PAX')
        if key in ['mtime', 'atime', 'ctime']:
            require(bool(re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?', text)), 'invalid time PAX')
        found[key] = text
        data = data[size:]
    return found


def scan_layer(value):
    """Inspect raw extension records before tarfile can consume/drop them."""
    stream = _stream(value)
    count = size_total = 0
    zeros = 0
    pending = {}
    seen = set()
    while True:
        header = stream.read(512)
        require(len(header) == 512, 'truncated tar/end marker')
        size_total += 512
        require(size_total <= MAX_BYTES, 'layer byte limit')
        if not any(header):
            zeros += 1
            if zeros == 2:
                require(not pending, 'dangling PAX header')
                while True:
                    tail = stream.read(65536)
                    if not tail:
                        return count
                    size_total += len(tail)
                    require(not any(tail) and size_total <= MAX_BYTES, 'nonzero tar tail or byte limit')
            continue
        require(zeros == 0, 'single zero before tar member')
        require(header[257:263] == b'ustar\x00' and header[263:265] == b'00' and not any(header[500:512]), 'unsupported tar header format')
        for numeric in [header[100:108], header[108:116], header[116:124], header[136:148], header[329:337], header[337:345]]:
            value = numeric.strip(b'\x00 ')
            require(not value or all(c in b'01234567' for c in value), 'unsupported numeric header')
        require(int(header[329:337].strip(b'\x00 ') or b'0', 8) == 0 and int(header[337:345].strip(b'\x00 ') or b'0', 8) == 0, 'unexpected device metadata')
        checksum_field = header[148:156].strip(b'\x00 ')
        require(checksum_field and all(c in b'01234567' for c in checksum_field), 'invalid checksum')
        require(sum(header[:148]) + 8*32 + sum(header[156:]) == int(checksum_field, 8), 'tar checksum mismatch')
        raw_size = header[124:136].strip(b'\x00 ')
        require(not raw_size or all(c in b'01234567' for c in raw_size), 'unsupported tar size encoding')
        size = int(raw_size or b'0', 8)
        require(0 <= size <= MAX_BYTES, 'member byte limit')
        typ = header[156:157]
        require(typ in [b'\x00', b'0', b'1', b'2', b'5', b'x'], 'unsupported tar type/global metadata')
        if typ == b'x':
            require(not pending and size <= 1_048_576, 'ambiguous or oversized PAX')
            data = stream.read(size)
            require(len(data) == size, 'truncated PAX')
            pending = _pax(data)
        else:
            name = header[:100].split(b'\x00')[0].decode('utf-8')
            prefix = header[345:500].split(b'\x00')[0].decode('utf-8')
            name = pending.get('path', (prefix + '/' if prefix else '') + name)
            name = safe_name(name)
            require(name not in seen, 'duplicate layer member')
            seen.add(name)
            if 'size' in pending:
                require(pending['size'].isdigit() and int(pending['size']) == size, 'ambiguous PAX size')
            if typ in [b'1', b'2']:
                link = pending.get('linkpath', header[157:257].split(b'\x00')[0].decode('utf-8'))
                require(link and '\x00' not in link, 'invalid link')
                if typ == b'1':
                    safe_name(link)
            if PurePosixPath(name).name.startswith('.wh.'):
                require(typ in [b'\x00', b'0'] and size == 0, 'invalid whiteout')
            remaining = size
            while remaining:
                data = stream.read(min(65536, remaining))
                require(data, 'truncated member')
                remaining -= len(data)
            pending = {}
            count += 1
            require(count <= MAX_MEMBERS, 'member count limit')
        padding = (-size) % 512
        require(len(stream.read(padding)) == padding, 'truncated padding')
        size_total += size + padding


def export_inventory(value, timestamps=None):
    stream = _stream(value)
    scan_layer(stream)
    stream.seek(0)
    rows = {}
    links = {}
    with tarfile.open(fileobj=stream, mode='r:') as archive:
        for h in archive:
            name = safe_name(h.name)
            require(name not in rows and len(rows) < MAX_MEMBERS, 'duplicate export member')
            require(h.isreg() or h.isdir() or h.issym() or h.islnk(), 'unsupported export member')
            if timestamps is not None:
                timestamps[name] = {'mtime': h.mtime, **{k: v for k, v in h.pax_headers.items() if k in ['mtime', 'atime', 'ctime']}}
            metadata = [h.type.hex(), h.mode, h.uid, h.gid]
            if h.isreg():
                content = archive.extractfile(h)
                digest = hashlib.sha256()
                total = 0
                while data := content.read(65536):
                    total += len(data)
                    require(total <= MAX_BYTES, 'content limit')
                    digest.update(data)
                require(total == h.size, 'truncated export content')
                metadata += [h.size, digest.hexdigest()]
            elif h.issym():
                metadata += [h.linkname]
            elif h.islnk():
                target = safe_name(h.linkname)
                require(target in rows and rows[target][0] in ['30', '00'], 'forward or ambiguous hardlink')
                metadata = rows[target].copy()
                require(metadata[1:4] == [h.mode, h.uid, h.gid], 'hardlink metadata mismatch')
                links[name] = links.get(target, target)
            rows[name] = metadata
    groups = {}
    for name, row in rows.items():
        if row[0] in ['30', '00']:
            groups.setdefault(links.get(name, name), []).append(name)
    for names in groups.values():
        for name in names:
            rows[name] += [tuple(sorted(names))]
    return rows


def assert_no_volumes(image):
    require(not image.get('Config', {}).get('Volumes'), 'image volumes unsupported')
    require(not image.get('Mounts'), 'container mounts unsupported')
    host = image.get('HostConfig', {})
    for key in ['Binds', 'Tmpfs', 'Privileged', 'UsernsMode']:
        require(not host.get(key), 'container mount/remapping unsupported')


def assert_same_config(a, b):
    require({k: a.get(k) for k in ['Config', 'Os', 'Architecture', 'Variant']} == {k: b.get(k) for k in ['Config', 'Os', 'Architecture', 'Variant']}, 'execution config/platform mismatch')


def assert_loaded_identity(image, config_digest, config):
    require(image['Id'] == config_digest, 'loaded config digest mismatch')
    require(image['RootFS']['Layers'] == config['rootfs']['diff_ids'], 'loaded diffIDs mismatch')
    require(image['Os'] == config['os'] == 'linux' and image['Architecture'] == config['architecture'] == 'amd64', 'platform mismatch')
    require(image.get('Variant', '') == config.get('variant', ''), 'platform variant mismatch')


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify_context(context, tracked):
    expected, directories, gitlinks = {}, set(), set()
    for record in tracked.split(b'\0'):
        if not record:
            continue
        descriptor, raw_path = record.split(b'\t')
        mode, kind, blob = descriptor.decode().split()
        path = safe_name(raw_path.decode())
        for parent in PurePosixPath(path).parents:
            if str(parent) != '.':
                directories.add(str(parent))
        if kind == 'commit':
            require(mode == '160000', 'unknown gitlink mode')
            gitlinks.add(path)
        else:
            require(kind == 'blob' and mode in ['100644', '100755', '120000'], 'unsupported context Git type')
            expected[path] = (mode, blob)
    actual, actual_dirs = set(), set()
    for base, dirs, files in os.walk(context, followlinks=False):
        for name in dirs + files:
            dest = Path(base) / name
            path = dest.relative_to(context).as_posix()
            info = dest.lstat()
            if stat.S_ISDIR(info.st_mode):
                require(path in directories or path in gitlinks, 'unexpected context directory')
                if path in gitlinks:
                    require(not list(dest.iterdir()), 'nonempty gitlink placeholder')
                actual_dirs.add(path)
                continue
            require(path in expected, 'unexpected context file/type')
            mode, blob = expected[path]
            if mode == '120000':
                require(stat.S_ISLNK(info.st_mode), 'context symlink type drift')
                data = os.readlink(dest).encode()
            else:
                require(stat.S_ISREG(info.st_mode), 'context regular file type drift')
                require(bool(info.st_mode & 0o111) == (mode == '100755'), 'context mode drift')
                require(info.st_size <= MAX_BYTES, 'context file limit')
                data = dest.read_bytes()
            require(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == blob, 'context blob drift')
            actual.add(path)
    require(actual == set(expected) and directories <= actual_dirs, 'context membership missing')
    # Git archives may omit or emit empty gitlink placeholders; no descendants,
    # foreign source or extra file is admitted in either representation.
    return {'files': len(actual), 'gitlinkPlaceholders': sorted(actual_dirs & gitlinks), 'gitObjectInventoryHash': fingerprint(expected)}


def selected_oci_material(materials, root, platform_manifest):
    """BuildKitv0.33.1 slsaMaterials: Local image -> pkg:oci PURL."""
    valid = {root, platform_manifest}
    matches = []
    for material in materials:
        uri = material.get('uri', '')
        parsed = urlsplit(uri)
        if parsed.scheme != 'pkg' or not parsed.path.startswith('oci/'):
            continue
        require(not parsed.netloc and not parsed.fragment, 'unknown OCI PURL shape')
        require(re.fullmatch(r'oci/[A-Za-z0-9._/@:+-]+', unquote(parsed.path)), 'unknown OCI PURL name')
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        require(len(pairs) == 2 and {k for k, _ in pairs} == {'digest', 'platform'}, 'unknown OCI PURL qualifiers')
        qualifiers = dict(pairs)
        require(qualifiers['digest'] in valid and qualifiers['platform'] == 'linux/amd64', 'OCI material input identity/platform mismatch')
        require(material.get('digest') in [{'sha256': value.split(':')[1]} for value in valid], 'OCI selected material digest mismatch')
        matches.append({'uriHash': fingerprint(uri), 'inputDigest': qualifiers['digest'], 'selectedDigest': 'sha256:'+material['digest']['sha256']})
    require(len(matches) == 1, 'selected immutable OCI material missing or ambiguous')
    return matches[0]


def oci(layout, scan=False, receipt=None):
    index = json.loads((layout / 'index.json').read_bytes())
    require(len(index['manifests']) == 1, 'ambiguous OCI layout root')
    def blob(desc):
        digest = desc['digest']
        require(DIGEST.fullmatch(digest), 'unknown OCI digest')
        path = layout / 'blobs' / 'sha256' / digest.split(':')[1]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == desc['size'], 'OCI blob size/type')
        h = hashlib.sha256()
        with path.open('rb') as f:
            while data := f.read(65536):
                h.update(data)
        require('sha256:' + h.hexdigest() == digest, 'OCI blob digest')
        return path
    root = index['manifests'][0]
    candidates = []
    def walk(desc, depth=0):
        require(depth <= 2, 'nested OCI index limit')
        value = json.loads(blob(desc).read_bytes())
        if 'manifests' in value:
            require(len(value['manifests']) <= 4, 'OCI index membership limit')
            for child in value['manifests']:
                walk(child, depth+1)
            return
        require('config' in value and 'layers' in value, 'unknown OCI object')
        cfg = json.loads(blob(value['config']).read_bytes())
        for layer in value['layers']:
            blob(layer)
        if desc.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest':
            require(cfg.get('architecture') == 'unknown' and cfg.get('os') == 'unknown', 'invalid attestation descriptor')
            return
        require(cfg.get('os') == 'linux' and cfg.get('architecture') == 'amd64', 'unreviewed OCI platform member')
        candidates.append((desc['digest'], value, cfg))
    walk(root)
    require(len(candidates) == 1, 'ambiguous OCI platform result')
    selected, manifest, config = candidates[0]
    require(config['os'] == 'linux' and config['architecture'] == 'amd64', 'OCI platform')
    require(len(manifest['layers']) == len(config['rootfs']['diff_ids']), 'layer/diffID count')
    for layer, diffid in zip(manifest['layers'], config['rootfs']['diff_ids']):
        path = blob(layer)
        media = layer['mediaType']
        require(media in ['application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.oci.image.layer.v1.tar'], 'unsupported layer compression')
        opener = gzip.open if media.endswith('+gzip') else open
        h = hashlib.sha256()
        total = 0
        with opener(path, 'rb') as f:
            while data := f.read(65536):
                total += len(data)
                require(total <= MAX_BYTES, 'uncompressed layer limit')
                h.update(data)
        require('sha256:' + h.hexdigest() == diffid, 'uncompressed diffID mismatch')
        if scan:
            with opener(path, 'rb') as f:
                scan_layer(f)
    if receipt is not None:
        receipt.update({'outputDigest': root['digest'], 'selectedManifestDigest': selected, 'configDigest': manifest['config']['digest'], 'layers': [x['digest'] for x in manifest['layers']], 'diffIDs': config['rootfs']['diff_ids'], 'platform': {'os': config['os'], 'architecture': config['architecture'], 'variant': config.get('variant', '')}})
    return root['digest'], manifest['config']['digest'], config, selected


class OwnedCommands:
    def __init__(self, directory):
        self.directory = directory
        self.deadline = time.monotonic() + 1200
        self.counter = 0
        self.receipts = []
        self.phase = "initialization"

    def run(self, args, *, output=None, allow_failure=False, cleanup=False):
        self.counter += 1
        path = output or self.directory / f'command-{self.counter}.log'
        # Reserve five minutes inside the20min total for at most8 containers
        # and2 tags; each cleanup attempt remains individually bounded.
        budget = min(30, max(0, self.deadline-time.monotonic())) if cleanup else min(600, max(0, self.deadline-time.monotonic()-300))
        require(budget > 0, 'audit deadline')
        env = {**os.environ, 'BUILDX_METADATA_PROVENANCE': 'max'}
        # Child processes receive ordinary CI authority only. No runtime secrets.
        with path.open('wb') as log:
            child = subprocess.Popen(args, stdout=log, stderr=log if output is None else subprocess.DEVNULL, env=env, start_new_session=True)
            started = time.monotonic()
            try:
                while child.poll() is None:
                    require(time.monotonic() - started < budget, 'owned command timeout')
                    require(path.stat().st_size <= (MAX_BYTES if output else 16*1024**2), 'owned command output limit')
                    time.sleep(0.2)
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
                self.receipts.append({"phase": self.phase, "action": " ".join(args[:2]), "seconds": round(time.monotonic()-started, 3), "bytes": path.stat().st_size, "exit": child.returncode})
        if not allow_failure:
            require(child.returncode == 0, 'owned command failed (output not serialized)')
        data = b'' if output else path.read_bytes()
        return child.returncode, data


def _json(commands, args):
    _, data = commands.run(args)
    require(len(data) <= 2*1024**2, 'JSON output limit')
    return json.loads(data)


def qualify():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-sha', required=True)
    opts = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', opts.source_sha), 'source SHA syntax')
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'cogni-test-org/cogni-monorepo', 'TEST hosted CI only')
    require(os.environ.get('GITHUB_EVENT_NAME') == 'pull_request' and os.environ.get('GITHUB_HEAD_REF') == 'test/task5314-copy-equivalence-qualification' and os.environ.get('GITHUB_BASE_REF') == 'test/task5314-current-source-base-83d5-f9dc', 'exact ordinary Q PR only')
    event_path = Path(os.environ['GITHUB_EVENT_PATH'])
    require(event_path.stat().st_size <= 2*1024**2, 'event payload limit')
    pr = json.loads(event_path.read_bytes())['pull_request']
    require(pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == 'cogni-test-org/cogni-monorepo', 'same TEST repository required')
    require(pr['head']['sha'] == opts.source_sha and pr['base']['sha'] == BASE, 'exact event source/base mismatch')
    source = Path.cwd()
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == opts.source_sha, 'checkout/source mismatch')
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD^'], text=True).strip() == BASE, 'qualification parent mismatch')
    old, new = base_recipe(source), (source / RECIPE).read_text()
    assert_recipe(old, new)
    owned = Path(tempfile.mkdtemp(prefix='copy-audit-', dir=os.environ['RUNNER_TEMP']))
    commands = OwnedCommands(owned)
    images, containers = [], []
    primary = None
    cleanup_errors = []
    summary = {'qualificationOnly': True, 'sourceSha': opts.source_sha, 'baseSha': BASE, 'started': time.time(), 'result': 'failed'}
    def interrupted(_signum, _frame):
        raise ValueError('audit cancelled')
    previous = {s: signal.signal(s, interrupted) for s in [signal.SIGINT, signal.SIGTERM]}
    try:
        engine = _json(commands, ['docker', 'version', '--format', '{{json .Server}}'])
        require(engine['Version'] == '29.4.2', 'unreviewed export-engine version')
        info = _json(commands, ['docker', 'info', '--format', '{{json .}}'])
        require(not any('rootless' in x or 'userns' in x for x in info.get('SecurityOptions', [])), 'unreviewed daemon remapping')
        summary['engineVersion'] = engine['Version']
        summary['storageDriver'] = info['Driver']
        archive = owned / 'context.tar'
        commands.run(['git', 'archive', '--format=tar', opts.source_sha], output=archive)
        context = owned / 'context'
        context.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(context, filter='data')
        # Bind every archived tracked file after extraction; excludes only gitlinks.
        tracked = subprocess.check_output(['git', 'ls-tree', '-rz', opts.source_sha])
        summary['context'] = verify_context(context, tracked)
        def pin(reference):
            _, data = commands.run(['docker', 'buildx', 'imagetools', 'inspect', reference])
            values = re.findall(rb'^Digest:\s*(sha256:[a-f0-9]{64})\s*$', data, re.M)
            require(len(values) == 1, 'registry reference digest unknown')
            return reference + '@' + values[0].decode()
        _, bx = commands.run(['docker', 'buildx', 'version'])
        require(re.search(rb' v0\.38\.0(?: |\n|$)', bx), 'unreviewed Buildx version')
        _, bk = commands.run(['docker', 'buildx', 'inspect', '--bootstrap'])
        require(re.search(rb'BuildKit(?: version)?:\s+v0\.33\.1(?:\s|$)', bk), 'unreviewed BuildKit version')
        summary['buildxVersion'] = '0.38.0'
        summary['buildkitVersion'] = '0.33.1'
        base = pin('node:22-alpine')
        frontend = pin('docker/dockerfile:1.7-labs')
        summary['baseReference'] = base
        summary['frontendReference'] = frontend
        def program(body, label):
            require(body.count('# syntax=docker/dockerfile:1.7-labs') == 1 and body.count('FROM node:22-alpine AS ') == 2, 'unexpected recipe references')
            body = body.replace('# syntax=docker/dockerfile:1.7-labs', '# syntax='+frontend).replace('FROM node:22-alpine AS ', 'FROM '+base+' AS ')
            path = owned / (label+'.Dockerfile')
            path.write_text(body)
            return path
        oldfile, newfile = program(old, 'old'), program(new, 'new')
        summary['recipeHashes'] = {p.stem: hashlib.sha256(p.read_bytes()).hexdigest() for p in [oldfile, newfile]}
        builder_layout = owned / 'builder-oci'
        builder_meta = owned / 'builder-metadata.json'
        common = ['docker', 'buildx', 'build', '--platform', 'linux/amd64', '--provenance=mode=max', '--build-arg', 'BUILD_SHA='+opts.source_sha]
        commands.phase = 'builder-export'
        commands.run(common+['--file', str(newfile), '--target', 'builder', '--output', f'type=oci,tar=false,dest={builder_layout}', '--metadata-file', str(builder_meta), str(context)])
        summary['builder'] = {}
        builder_digest, _, _, builder_manifest = oci(builder_layout, receipt=summary['builder'])
        metadata = json.loads(builder_meta.read_bytes())
        require(metadata.get('containerimage.digest') == builder_digest, 'builder output/metadata identity mismatch')
        summary['builderDigest'] = builder_digest
        image_records, inventories = [], []
        for label, recipe in [('old', oldfile), ('new', newfile)]:
            commands.phase = 'runner-'+label
            require(oci(builder_layout)[0] == builder_digest, 'builder changed')
            tag = f'copy-audit-{os.environ["GITHUB_RUN_ID"]}-{os.environ["GITHUB_RUN_ATTEMPT"]}:{label}'
            images.append(tag)
            layout, meta = owned / (label+'-oci'), owned / (label+'-metadata.json')
            commands.run(common+['--file', str(recipe), '--target', 'runner', '--build-context', f'builder=oci-layout://{builder_layout}@{builder_digest}', '--tag', tag, '--output', f'type=oci,tar=false,dest={layout}', '--load', '--metadata-file', str(meta), str(context)])
            m = json.loads(meta.read_bytes())
            provenance = m.get('buildx.build.provenance', {})
            materials = provenance.get('materials', [])
            record = {'layout': label, 'builderMaterial': selected_oci_material(materials, builder_digest, builder_manifest)}
            _, config_digest, config, _ = oci(layout, scan=True, receipt=record)
            summary.setdefault('auditImages', []).append(record)
            image = _json(commands, ['docker', 'image', 'inspect', tag])[0]
            assert_loaded_identity(image, config_digest, config)
            assert_no_volumes(image)
            image_records.append(image)
            container = 'copy-audit-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']+'-'+label
            containers.append(container)
            _, out = commands.run(['docker', 'create', '--name', container, '--network', 'none', tag])
            require(re.fullmatch('[a-f0-9]{64}', out.decode().strip()), 'container ID')
            assert_no_volumes(_json(commands, ['docker', 'container', 'inspect', container])[0])
            exported = owned / (label+'.tar')
            commands.run(['docker', 'export', container], output=exported)
            timestamps = {}
            with exported.open('rb') as f:
                inventory = export_inventory(f, timestamps)
                inventories.append(inventory)
            record['executionConfigHash'] = fingerprint({k: image.get(k) for k in ['Config', 'Os', 'Architecture', 'Variant']})
            record['filesystemInventoryHash'] = fingerprint(inventory)
            record['timestampProvenanceHash'] = fingerprint(timestamps)
            record['timestampPolicy'] = 'record-only: all filesystem times; Moby export truncates mtime and omits atime/ctime; complete source times remain bound by recorded layer digests'
            record['filesCompared'] = len(inventory)
            require(verify_context(context, tracked) == summary['context'], 'context changed after build')
            require(oci(builder_layout)[0] == builder_digest, 'builder changed after runner build')
        assert_same_config(*image_records)
        require(inventories[0] == inventories[1], 'complete admitted rootfs mismatch')
        summary['filesCompared'] = len(inventories[0])
        smoke = "const a=await import('/app/node_modules/@cogni-dao/doltgres-admission/dist/index.js');for(const k of ['DoltBranchMutationUncertainError','DoltNativeSessionExecutor','runDoltBranchMutation'])if(typeof a[k]!=='function')throw Error('missing released export');const m=await import('/app/nodes/operator/app/migrate-doltgres.mjs');const v=await import('/app/nodes/operator/app/verify-doltgres-schema.mjs');if(typeof m.migrateDoltgres!=='function'||typeof v.verifyDoltgresSchema!=='function')throw Error('missing migration export');"
        def smoke_container(tag, arguments, expected):
            identifier = 'copy-audit-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']+'-smoke-'+str(len(containers))
            containers.append(identifier)
            _, out = commands.run(['docker', 'create', '--name', identifier, '--network', 'none', '--env', 'DATABASE_URL=', '--entrypoint', 'node', tag] + arguments)
            require(re.fullmatch('[a-f0-9]{64}', out.decode().strip()), 'smoke container ID')
            assert_no_volumes(_json(commands, ['docker', 'container', 'inspect', identifier])[0])
            _, output = commands.run(['docker', 'start', '--attach', identifier], allow_failure=True)
            state = _json(commands, ['docker', 'container', 'inspect', identifier])[0]['State']
            require(not state['Running'] and state['ExitCode'] == expected, 'actual image smoke exit mismatch')
            if expected == 2:
                require(b'DATABASE_URL is required' in output, 'actual CLI missing-URL reason mismatch')
        for tag in images:
            commands.phase = 'smoke-'+tag.rsplit(':', 1)[1]
            # Explicit IDs are retained before start; timeout/cancel always removes
            # the actual owned daemon-side containers, not only the Docker client.
            smoke_container(tag, ['--input-type=module', '-e', smoke], 0)
            for script in ['migrate.mjs', 'migrate-doltgres.mjs']:
                smoke_container(tag, ['/app/nodes/operator/app/'+script], 2)
        summary['result'] = 'passed'
    except BaseException as error:
        primary = error
        summary['failureClass'] = type(error).__name__
        summary['failure'] = str(error)[:200]
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        commands.phase = 'cleanup'
        for command in [['docker', 'rm', '-f', x] for x in containers] + [['docker', 'image', 'rm', '-f', x] for x in images]:
            try:
                commands.run(command, cleanup=True)
            except BaseException:
                cleanup_errors.append('owned resource cleanup failed')
        summary['seconds'] = round(time.time()-summary['started'], 3)
        summary['cleanupErrors'] = len(cleanup_errors)
        if cleanup_errors:
            summary['result'] = 'failed'
        try:
            shutil.rmtree(owned)
        except BaseException:
            cleanup_errors.append('owned temporary cleanup failed')
            summary['result'] = 'failed'
        summary['cleanupErrors'] = len(cleanup_errors)
        summary['ownedCommands'] = commands.receipts
        # Public identities/counts/static diagnostics, never Env/config/contents.
        print(json.dumps(summary), flush=True)
        for sig, old_handler in previous.items():
            signal.signal(sig, old_handler)
    if primary:
        raise primary
    require(not cleanup_errors, 'owned cleanup failed')


if __name__ == '__main__':
    try:
        qualify()
    except BaseException as error:
        print('COPY qualification RED: '+type(error).__name__, file=sys.stderr)
        sys.exit(1)
