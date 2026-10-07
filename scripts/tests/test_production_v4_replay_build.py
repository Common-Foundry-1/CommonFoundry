"""GPU-free regression tests for actual replay compile and artifact-gate arguments."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / 'tools/production-v4-prover/build-replay.sh'
ARCHITECTURES = (70, 75, 80, 86, 89, 90, 120)


@unittest.skipIf(os.name == 'nt', 'Run under Linux/WSL, without a GPU or real compiler')
class ReplayBuildTests(unittest.TestCase):
    def run_build(self, *, existing=False, intermediates=False, arguments=(), **overrides):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mock = root / 'bin'
            mock.mkdir()
            commands = {
                'git': '''#!/bin/sh
case "$3" in
rev-parse) echo "${TEST_PIN:-ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e}";;
status) printf '%s' "${TEST_DIRTY:-}";;
*) exit 1;;
esac
''',
                'nvcc': '''#!/bin/sh
if [ "$1" = --help ]; then
  echo "${TEST_OPTIONS:---frandom-seed}"
  exit 0
fi
if [ "$1" = --list-gpu-code ]; then
  printf '%s\\n' ${TEST_TARGETS:-sm_70 sm_75 sm_80 sm_86 sm_89 sm_90 sm_120}
  exit 0
fi
printf '%s\\n' "$@" > "$TEST_ARGS"
while [ "$1" != -o ]; do shift; done
printf 'test artifact' > "$2"
''',
                'cuobjdump': '''#!/bin/sh
case "$1" in
--list-elf) printf '%s\\n' ${TEST_IMAGES:-sm_70.cubin sm_75.cubin sm_80.cubin sm_86.cubin sm_89.cubin sm_90.cubin sm_120.cubin};;
--list-ptx) echo "${TEST_PTX:-sm_70.ptx}";;
*) exit 1;;
esac
''',
            }
            for name, content in commands.items():
                path = mock / name
                path.write_text(content)
                path.chmod(0o755)
            output = root / 'output'
            if existing:
                output.mkdir()
                (output / 'cmfd-v4-replay').write_bytes(b'preserved worker')
            if intermediates:
                (output / 'cuda-intermediates').mkdir(parents=True, exist_ok=True)
            environment = dict(os.environ, PATH=f"{mock}:{os.environ['PATH']}",
                               CUDACXX=str(mock / 'nvcc'), CMFD_CUOBJDUMP=str(mock / 'cuobjdump'),
                               CMFD_CUTLASS_ROOT=str(root / 'cutlass'), TEST_ARGS=str(root / 'args'), **overrides)
            result = subprocess.run(['bash', str(BUILD), str(output), *arguments], env=environment,
                                    text=True, capture_output=True, timeout=15)
            captured = root / 'args'
            artifact = output / 'cmfd-v4-replay'
            return result, captured.read_text() if captured.exists() else '', artifact.read_bytes() if artifact.exists() else b''

    def test_all_native_images_and_portable_ptx_are_requested(self):
        result, arguments, _ = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        for architecture in ARCHITECTURES:
            self.assertIn(f'--generate-code=arch=compute_{architecture},code=sm_{architecture}', arguments)
        self.assertIn('--generate-code=arch=compute_70,code=compute_70', arguments)

    def test_wrong_or_dirty_dependency_is_rejected_before_compile(self):
        for options in ({'TEST_PIN': 'wrong'}, {'TEST_DIRTY': ' M header.h'}):
            with self.subTest(options=options):
                result, arguments, _ = self.run_build(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(arguments, '')

    def test_every_missing_compiler_target_is_rejected_before_compile(self):
        for missing in ARCHITECTURES:
            with self.subTest(missing=missing):
                targets = ' '.join(f'sm_{value}' for value in ARCHITECTURES if value != missing)
                result, arguments, _ = self.run_build(TEST_TARGETS=targets)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(arguments, '')

    def test_every_missing_native_image_is_rejected_after_compile(self):
        for missing in ARCHITECTURES:
            with self.subTest(missing=missing):
                images = ' '.join(f'sm_{value}.cubin' for value in ARCHITECTURES if value != missing)
                result, _, _ = self.run_build(TEST_IMAGES=images)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('missing its native', result.stderr)

    def test_prefix_match_cannot_supply_a_missing_native_image(self):
        images = ' '.join(f'sm_{value}.cubin' for value in ARCHITECTURES if value != 70) + ' sm_700.cubin'
        result, _, _ = self.run_build(TEST_IMAGES=images)
        self.assertNotEqual(result.returncode, 0)

    def test_missing_wrong_or_prefix_only_ptx_is_rejected(self):
        for ptx in ('no PTX', 'sm_75.ptx', 'sm_700.ptx'):
            with self.subTest(ptx=ptx):
                result, _, _ = self.run_build(TEST_PTX=ptx)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('missing its compute_70', result.stderr)

    def test_existing_artifact_is_preserved(self):
        result, arguments, artifact = self.run_build(existing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(arguments, '')
        self.assertEqual(artifact, b'preserved worker')

    def test_print_plan_never_executes_compiler(self):
        result, arguments, _ = self.run_build(arguments=('--print-build-plan',), TEST_PIN='wrong')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(arguments, '')
        self.assertIn('REPLAY_NATIVE_ARCHS=70 75 80 86 89 90 120', result.stdout)
        compile_line = next(line for line in result.stdout.splitlines() if line.startswith('REPLAY_COMPILE='))
        self.assertIn('--generate-code=arch=compute_70,code=compute_70',
                      shlex.split(compile_line.removeprefix('REPLAY_COMPILE=')))

    def test_duplicate_or_unknown_options_are_rejected(self):
        for options in (('--bad',), ('--print-build-plan', '--print-build-plan'),
                        ('--reproducible', '--reproducible'), ('another-output',)):
            result, arguments, _ = self.run_build(arguments=options)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(arguments, '')

    def test_reproducible_mode_passes_seed_and_keeps_intermediates(self):
        result, arguments, _ = self.run_build(arguments=('--reproducible',))
        self.assertEqual(result.returncode, 0, result.stderr)
        flags = arguments.splitlines()
        self.assertIn('--frandom-seed=1129137732', flags)
        self.assertIn('--keep', flags)
        self.assertIn('--objdir-as-tempdir', flags)
        self.assertTrue(flags[flags.index('--keep-dir') + 1].endswith('/cuda-intermediates'))

    def test_reproducible_mode_rejects_unsupported_compiler_before_compile(self):
        result, arguments, artifact = self.run_build(arguments=('--reproducible',), TEST_OPTIONS='old compiler')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('require CUDA 12.9', result.stderr)
        self.assertEqual(arguments, '')
        self.assertEqual(artifact, b'')

    def test_large_compiler_help_cannot_fail_due_to_grep_sigpipe(self):
        result, _, _ = self.run_build(arguments=('--reproducible',),
                                      TEST_OPTIONS='--frandom-seed\n' + 'more help\n' * 4000)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reproducible_mode_preserves_existing_intermediates(self):
        result, arguments, _ = self.run_build(arguments=('--reproducible',), intermediates=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Preserve existing CUDA intermediates', result.stderr)
        self.assertEqual(arguments, '')

    def test_reproducible_print_plan_needs_no_supported_compiler(self):
        result, arguments, _ = self.run_build(arguments=('--reproducible', '--print-build-plan'),
                                               TEST_OPTIONS='old compiler', TEST_PIN='wrong')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(arguments, '')
        self.assertIn('--frandom-seed=1129137732', result.stdout)

    def test_full_prover_build_delegates_replay_and_preserves_proof_targets(self):
        source = (BUILD.parent / 'build.sh').read_text()
        self.assertIn('bash "$SCRIPT_DIR/build-replay.sh"', source)
        self.assertNotIn('koala_four_limb_replay.cu', source)
        self.assertIn("CUDA_ARCHS='86;89;120'", source)

    def test_replay_kernel_namespace_does_not_embed_checkout_path(self):
        source = (BUILD.parent / 'cuda/koala_four_limb_replay.cu').read_text()
        self.assertIn('namespace cmfd_v4_replay {', source)
        self.assertIn('using namespace cmfd_v4_replay;', source)
        self.assertNotRegex(source, r'\bnamespace\s*\{')

    def test_build_scripts_parse(self):
        for name in ('build-replay.sh', 'build.sh', 'test-build-arguments.sh'):
            result = subprocess.run(['bash', '-n', str(BUILD.parent / name)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
