"""TEST-only source/layout audit controls; no Docker, registry or network."""
import importlib.util
import io
import json
import hashlib
import tempfile
import time
import sys
import subprocess
import re
import textwrap
import os
from pathlib import Path
import tarfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'qualify-operator-copy-layout.py'
spec = importlib.util.spec_from_file_location('copy_audit', MODULE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def archive(rows):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name, data, attrs in rows:
            h = tarfile.TarInfo(name)
            h.size = len(data)
            h.mode = 0o644
            for key, value in attrs.items():
                setattr(h, key, value)
            tar.addfile(h, io.BytesIO(data))
    return out.getvalue()


class AuditControls(unittest.TestCase):
    def test_exact_reviewed_engine_and_unknown_version_receipt(self):
        known = {'Version': '28.0.4', 'Os': 'linux', 'Arch': 'amd64'}
        receipt = {}
        audit.record_engine_identity(receipt, known)
        self.assertEqual(receipt['engineVersion'], '28.0.4')
        for changed in [{'Version': '29.4.2'}, {'Os': 'windows'}, {'Arch': 'arm64'}]:
            with self.subTest(changed=changed):
                observed = {**known, **changed}
                receipt = {}
                with self.assertRaises(ValueError):
                    audit.record_engine_identity(receipt, observed)
                self.assertEqual(receipt['engineVersion'], observed['Version'])
                self.assertEqual(receipt['enginePlatform'], {'os': observed['Os'], 'architecture': observed['Arch']})

    def test_actual_migration_event_binding_preserves_real_immutable_negative(self):
        root = MODULE.parents[2]
        workflow = (root / '.github/workflows/ci.yaml').read_text()
        match = re.search(r'      - name: Database migration guards\n.*?        run: \|\n(.*?)(?=\n      (?:#|-))', workflow, re.S)
        self.assertIsNotNone(match)
        command = textwrap.dedent(match.group(1))
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(owned), *args], text=True, stderr=subprocess.DEVNULL).strip()
            git('init', '-q')
            git('config', 'user.name', 'Owned CI fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            migration = owned / 'infra/compose/runtime/postgres-init/control-migrations/0000_owned.sql'
            migration.parent.mkdir(parents=True)
            migration.write_text('SELECT 1;\n')
            old = owned / 'nodes/canary/app/src/adapters/server/db/migrations/0000_old.sql'
            old.parent.mkdir(parents=True)
            old.write_text('SELECT 2;\n')
            (old.parent / 'README.md').write_text('surviving node input')
            git('add', '.')
            git('commit', '-qm', 'owned historical main')
            git('update-ref', 'refs/remotes/origin/main', 'HEAD')
            old.unlink()
            git('add', '.')
            git('commit', '-qm', 'owned protected fixture baseline')
            base = git('rev-parse', 'HEAD')
            (owned / 'changed.txt').write_text('ordinary nonmigration delta')
            git('add', '.')
            git('commit', '-qm', 'owned PR')
            tools = owned / 'bin'
            tools.mkdir()
            shim = tools / 'pnpm'
            shim.write_text('#!/bin/sh\n[ "$1" = db:check ] || exit 91\nexec node "$OWNED_MIGRATION_GUARD"\n')
            shim.chmod(0o755)
            environment = {**os.environ, 'PATH': str(tools)+os.pathsep+os.environ['PATH'], 'OWNED_MIGRATION_GUARD': str(root / 'scripts/db/check-migrations-immutable.mjs'), 'MIGRATION_PR_BASE_SHA': base, 'MIGRATION_MQ_BASE_SHA': base}
            def execute(event='pull_request', **overrides):
                return subprocess.run(['bash', '-euo', 'pipefail', '-c', command], cwd=owned, env={**environment, 'GITHUB_EVENT_NAME': event, **overrides}, capture_output=True, text=True, timeout=10)
            # The wrong origin/main reports historical deletions; the actual PR
            # and MQ event bases admit exactly this unchanged migration tree.
            wrong = subprocess.run(['node', environment['OWNED_MIGRATION_GUARD']], cwd=owned, env={**environment, 'MIGRATIONS_BASE_REF': 'origin/main'}, capture_output=True, timeout=10)
            self.assertNotEqual(wrong.returncode, 0)
            self.assertEqual(execute().returncode, 0)
            self.assertEqual(execute('merge_group').returncode, 0)
            self.assertNotEqual(execute(MIGRATION_PR_BASE_SHA='untrusted;echo bypass').returncode, 0)
            self.assertNotEqual(execute(MIGRATION_PR_BASE_SHA='f'*40).returncode, 0)
            migration.write_text('SELECT 999;\n')
            rejected = execute()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('Migrations are append-only', rejected.stderr)

    def test_loaded_test_image_config_rejects_foreign_runtime_or_producer(self):
        helper = (MODULE.parent / 'qualify-test-doltgres-image.mjs').as_uri()
        program = r"""
import assert from 'node:assert/strict';
import {verifyLoadedFixture} from 'HELPER_URI';
const layer = 'sha256:'+'1'.repeat(64);
const base = {Id:'sha256:'+'2'.repeat(64),Os:'linux',Architecture:'amd64',RootFS:{Type:'layers',Layers:[layer]},Config:{Env:['PUBLIC=value'],Cmd:['doltgres'],Labels:{upstream:'preserved'}}};
const mirror = structuredClone(base);
mirror.Id = 'sha256:'+'3'.repeat(64);
mirror.RootFS.Layers.push('sha256:'+'4'.repeat(64));
mirror.Config.Labels = {...base.Config.Labels,'org.opencontainers.image.source':'https://github.com/cogni-test-org/cogni-monorepo','org.opencontainers.image.revision':'d0678db88ded712e60c2ffa472bc9be1fff45900','org.opencontainers.image.created':'2026-10-23T08:22:26Z'};
const receipt = verifyLoadedFixture(base,mirror);
assert(!JSON.stringify(receipt).includes('PUBLIC=value'));
// Only absent/empty platform fields are equivalent; preserve every nonempty value.
const empty=structuredClone(mirror);empty.Variant='';empty.OsVersion='';
verifyLoadedFixture(base,empty);
for (const alter of [x=>x.Config.Env=['ALTERED=value'],x=>x.Config.Unknown='new',x=>x.Config.Labels['org.opencontainers.image.revision']='f'.repeat(40),x=>x.RootFS.Layers[0]='sha256:'+'5'.repeat(64),x=>x.Architecture='arm64',x=>x.Variant='v3',x=>x.OsVersion='10.0.1',x=>x.Variant=null,x=>x.OsVersion=3]) {
 const bad=structuredClone(mirror);alter(bad);assert.throws(()=>verifyLoadedFixture(base,bad));
}
""".replace('HELPER_URI', helper)
        subprocess.run(['node', '--input-type=module', '-e', program], check=True, capture_output=True, timeout=10)

    def test_actual_seven_copy_move_is_only_change(self):
        root = MODULE.parents[2]
        old = audit.base_recipe(root)
        new = audit.relocate(old)
        audit.assert_recipe(old, new)
        if (root / 'nodes/operator/app/Dockerfile').read_text() != old:
            audit.assert_recipe(old, (root / 'nodes/operator/app/Dockerfile').read_text())
        self.assertEqual(new.count('COPY --from=builder'), old.count('COPY --from=builder'))
        with self.assertRaises(ValueError):
            audit.assert_recipe(old, new.replace('--chown=nextjs:nodejs /app/scripts/db/migrate.mjs', '--chown=root:root /app/scripts/db/migrate.mjs'))

    def test_complete_export_metadata_and_content(self):
        good = archive([('app/helper', b'actual', {})])
        self.assertEqual(audit.export_inventory(good), audit.export_inventory(good))
        for rows in [[('app/helper', b'changed', {})], [('app/helper', b'actual', {'uid': 9})], [('app/helper', b'actual', {'mode': 0o600})], []]:
            self.assertNotEqual(audit.export_inventory(good), audit.export_inventory(archive(rows)))
        for rows in [[('../escape', b'', {})], [('x', b'', {}), ('x', b'', {})], [('x', b'', {'type': tarfile.FIFOTYPE})]]:
            with self.assertRaises(ValueError):
                audit.export_inventory(archive(rows))

    def test_source_layer_metadata_absence_is_mandatory(self):
        audit.scan_layer(archive([('app/helper', b'ok', {'pax_headers': {'mtime': '1.5'}})]))
        for key in ['SCHILY.xattr.security.capability', 'SCHILY.xattr.user.test', 'SCHILY.acl.access', 'LIBARCHIVE.xattr.user.test', 'unknown']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit.scan_layer(archive([('app/helper', b'ok', {'pax_headers': {key: 'forbidden'}})]))
        # A forbidden attribute must fail even if a later whiteout removes it.
        with self.assertRaises(ValueError):
            audit.scan_layer(archive([('app/helper', b'ok', {'pax_headers': {'SCHILY.xattr.user.test': 'x'}}), ('app/.wh.helper', b'', {})]))

    def test_links_and_config_fail_closed(self):
        plain = audit.export_inventory(archive([('a', b'data', {}), ('link', b'', {'type': tarfile.SYMTYPE, 'linkname': 'a'})]))
        changed = audit.export_inventory(archive([('a', b'data', {}), ('link', b'', {'type': tarfile.SYMTYPE, 'linkname': 'b'})]))
        self.assertNotEqual(plain, changed)
        hard = audit.export_inventory(archive([('a', b'data', {}), ('link', b'', {'type': tarfile.LNKTYPE, 'linkname': 'a'})]))
        copies = audit.export_inventory(archive([('a', b'data', {}), ('link', b'data', {})]))
        self.assertNotEqual(hard, copies)
        audit.assert_no_volumes({'Config': {}, 'Mounts': [], 'HostConfig': {'Binds': None, 'Tmpfs': None, 'Privileged': False, 'UsernsMode': ''}})
        for x in [{'Config': {'Volumes': {'/data': {}}}}, {'Mounts': [{'Destination': '/data'}]}, {'HostConfig': {'Binds': ['x:/x']}}, {'HostConfig': {'Privileged': True}}]:
            with self.assertRaises(ValueError):
                audit.assert_no_volumes(x)
        with self.assertRaises(ValueError):
            audit.assert_same_config({'Config': {'Env': ['A=x']}, 'Os': 'linux'}, {'Config': {'Env': ['A=y']}, 'Os': 'linux'})

    def test_oci_identity_and_layer_digest_are_required(self):
        config = {'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + '1'*64]}}
        image = {'Id': 'sha256:' + '2'*64, 'RootFS': {'Layers': config['rootfs']['diff_ids']}, 'Os': 'linux', 'Architecture': 'amd64'}
        audit.assert_loaded_identity(image, 'sha256:' + '2'*64, config)
        with self.assertRaises(ValueError):
            audit.assert_loaded_identity({**image, 'Id': 'sha256:' + '3'*64}, 'sha256:' + '2'*64, config)
        with self.assertRaises(ValueError):
            audit.assert_loaded_identity({**image, 'RootFS': {'Layers': []}}, 'sha256:' + '2'*64, config)
        with self.assertRaises(ValueError):
            audit.verify_digest(b'changed layer', 'sha256:' + '1'*64)

    def test_real_oci_index_graph_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blobs = root / 'blobs/sha256'
            blobs.mkdir(parents=True)
            def store(data, media):
                digest = 'sha256:' + hashlib.sha256(data).hexdigest()
                (blobs / digest.split(':')[1]).write_bytes(data)
                return {'digest': digest, 'size': len(data), 'mediaType': media}
            layer = store(archive([('app/helper', b'data', {})]), 'application/vnd.oci.image.layer.v1.tar')
            config = {'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': [layer['digest']]}}
            cfg = store(json.dumps(config).encode(), 'application/vnd.oci.image.config.v1+json')
            manifest = store(json.dumps({'schemaVersion': 2, 'config': cfg, 'layers': [layer]}).encode(), 'application/vnd.oci.image.manifest.v1+json')
            index = store(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}).encode(), 'application/vnd.oci.image.index.v1+json')
            (root / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [index]}))
            result = audit.oci(root, scan=True)
            self.assertEqual(result[0], index['digest'])
            self.assertEqual(result[1], cfg['digest'])
            self.assertEqual(result[3], manifest['digest'])
            (blobs / layer['digest'].split(':')[1]).write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                audit.oci(root, scan=True)

    def test_buildkit_0331_modern_and_legacy_attestation_members(self):
        # Representative commitAttestationsManifest output, pinned BuildKit0.33.1:
        # modern OCI empty config + artifactType/subject; legacy unknown image config.
        def execute(modern=True, change=None, receipt=None):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                blobs = root / 'blobs/sha256'
                blobs.mkdir(parents=True)
                def store(data, media):
                    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
                    (blobs / digest.split(':')[1]).write_bytes(data)
                    return {'digest': digest, 'size': len(data), 'mediaType': media}
                media = 'application/vnd.oci.image.manifest.v1+json'
                layer = store(archive([('app/helper', b'data', {})]), 'application/vnd.oci.image.layer.v1.tar')
                config = {'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': [layer['digest']]}}
                cfg = store(json.dumps(config).encode(), 'application/vnd.oci.image.config.v1+json')
                runnable = store(json.dumps({'schemaVersion': 2, 'mediaType': media, 'config': cfg, 'layers': [layer]}).encode(), media)
                att_config = store(b'{}' if modern else json.dumps({'os': 'unknown', 'architecture': 'unknown'}).encode(), 'application/vnd.oci.empty.v1+json' if modern else 'application/vnd.oci.image.config.v1+json')
                att = {'schemaVersion': 2, 'mediaType': media, 'config': att_config, 'layers': [store(b'{"predicateType":"https://slsa.dev/provenance/v0.2"}', 'application/vnd.in-toto+json')]}
                descriptor = {'platform': {'os': 'unknown', 'architecture': 'unknown'}, 'annotations': {'vnd.docker.reference.type': 'attestation-manifest', 'vnd.docker.reference.digest': runnable['digest']}}
                if modern:
                    att.update(artifactType='application/vnd.docker.attestation.manifest.v1+json', subject=dict(runnable))
                if change:
                    change(att, descriptor, store)
                descriptor.update(store(json.dumps(att).encode(), media))
                index = store(json.dumps({'schemaVersion': 2, 'manifests': [runnable, descriptor]}).encode(), 'application/vnd.oci.image.index.v1+json')
                (root / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [index]}))
                return audit.oci(root, scan=True, receipt=receipt)
        for modern in [True, False]:
            receipt = {}
            execute(modern, receipt=receipt)
            self.assertEqual(len(receipt['observedManifests']), 2)
            self.assertIn('selectedManifestDigest', receipt)
            self.assertNotIn('predicateType', json.dumps(receipt))
        for change in [
            lambda a, d, st: a.pop('subject'),
            lambda a, d, st: a['subject'].update(digest='sha256:'+'f'*64),
            lambda a, d, st: a['subject'].update(size=a['subject']['size']+1),
            lambda a, d, st: a['subject'].update(mediaType='application/unknown'),
            lambda a, d, st: a.update(artifactType='application/unknown'),
            lambda a, d, st: a.update(config=st(b'{"unexpected":1}', 'application/vnd.oci.empty.v1+json')),
            lambda a, d, st: a['config'].update(digest='sha256:'+'f'*64),
            lambda a, d, st: a['config'].update(mediaType='application/vnd.oci.image.config.v1+json'),
            lambda a, d, st: d['annotations'].update({'vnd.docker.reference.digest':'sha256:'+'f'*64}),
            lambda a, d, st: d['platform'].update(architecture='amd64'),
            lambda a, d, st: a['layers'][0].update(mediaType='application/unknown'),
        ]:
            receipt = {}
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError)):
                execute(change=change, receipt=receipt)
            # Even rejected descriptors are observable after owned temp cleanup.
            self.assertEqual(len(receipt['observedManifests']), 2)
            self.assertIn('config', receipt['observedManifests'][1])
        with self.assertRaises(ValueError):
            execute(False, lambda a, d, st: a.update(config=st(b'{}', 'application/vnd.oci.image.config.v1+json')))

    def test_owned_timeout_kills_and_joins_child(self):
        with tempfile.TemporaryDirectory() as directory:
            commands = audit.OwnedCommands(Path(directory))
            commands.deadline = time.monotonic() + 300.05
            started = time.monotonic()
            with self.assertRaises(ValueError):
                commands.run([sys.executable, '-c', 'import time;time.sleep(30)'])
            self.assertLess(time.monotonic()-started, 2)

    def test_pinned_buildkit_oci_purl_and_wrong_materials(self):
        root, selected = 'sha256:'+'1'*64, 'sha256:'+'2'*64
        # BuildKitv0.33.1 predicate.go uses TypeOCI and purl/image.go
        # serializes canonical digest + normalized platform qualifiers.
        uri = 'pkg:oci/buildkit/oci-layout?digest=sha256%3A'+'1'*64+'&platform=linux%2Famd64'
        material = {'uri': uri, 'digest': {'sha256': '2'*64}}
        self.assertEqual(audit.selected_oci_material([material], root, selected)['selectedDigest'], selected)
        for bad in [[], [material, material], [{'uri': uri.replace('pkg:oci/', 'pkg:docker/'), 'digest': material['digest']}], [{'uri': uri, 'digest': {'sha256': '3'*64}}], [{'uri': uri.replace('linux%2Famd64', 'linux%2Farm64'), 'digest': material['digest']}], [{'uri': uri+'&unexpected=x', 'digest': material['digest']}]]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                audit.selected_oci_material(bad, root, selected)

    def test_context_exact_membership_types_modes_and_gitlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'input'
            path.write_bytes(b'actual')
            blob = hashlib.sha1(b'blob 6\0actual').hexdigest()
            tracked = ('100644 blob '+blob+'\tinput\0').encode()
            audit.verify_context(root, tracked)
            (root / 'unexpected').write_text('extra')
            with self.assertRaises(ValueError):
                audit.verify_context(root, tracked)
            (root / 'unexpected').unlink()
            path.unlink()
            outside = root.parent / (root.name+'-target')
            try:
                outside.write_bytes(b'actual')
                path.symlink_to(outside)
                with self.assertRaises(ValueError):
                    audit.verify_context(root, tracked)
            finally:
                path.unlink()
                outside.unlink()
            path.write_bytes(b'actual')
            path.chmod(0o755)
            with self.assertRaises(ValueError):
                audit.verify_context(root, tracked)
            path.chmod(0o644)
            (root / 'nodes').mkdir()
            (root / 'nodes/test').mkdir()
            tracked += ('160000 commit '+'1'*40+'\tnodes/test\0').encode()
            audit.verify_context(root, tracked)
            (root / 'nodes/test/foreign').write_text('unreviewed')
            with self.assertRaises(ValueError):
                audit.verify_context(root, tracked)

    def test_timestamp_receipt_persists_provenance_without_content(self):
        timestamps = {}
        inventory = audit.export_inventory(archive([('app/helper', b'private body', {'mtime': 123})]), timestamps)
        self.assertEqual(timestamps['app/helper']['mtime'], 123)
        receipt = {'filesystemInventoryHash': audit.fingerprint(inventory), 'timestampProvenanceHash': audit.fingerprint(timestamps)}
        self.assertNotIn('private body', json.dumps(receipt))
        self.assertNotEqual(receipt['timestampProvenanceHash'], audit.fingerprint({'app/helper': {'mtime': 124}}))


if __name__ == '__main__':
    unittest.main()
