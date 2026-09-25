"""Tests for the AppStrict compilation mode.

AppStrict restricts only application-owned Python source files selected by
path via --app-strict-root / --app-strict-exclude.  These tests exercise the
validator in-process by adding the current interpreter's AppStrict config
programmatically is NOT possible (configuration is command-line driven), so
we spawn subprocesses that run the built python with the relevant options.
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from test import support


# The interpreter currently running the test suite.
PYTHON = sys.executable or sys.argv[0]


def run_python(*args, cwd=None, env=None):
    """Run the current python with *args*, capture output."""
    cmd = [PYTHON] + list(args)
    e = dict(os.environ)
    e.update(env or {})
    p = subprocess.run(cmd, cwd=cwd, env=e,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True)
    return p.returncode, p.stdout, p.stderr


def write(root: Path, rel: str, src: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src))
    return p


class AppStrictTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="appstrict_")
        self.root = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def run_module(self, app_root: Path, module_file: Path,
                   *extra_args, cwd=None):
        """Compile & run *module_file* with *app_root* as strict root."""
        args = ["--app-strict-root", str(app_root)] + list(extra_args) + [str(module_file)]
        return run_python(*args, cwd=cwd or str(self.root))

    def compile_only(self, app_root: Path, src: str, name="main.py"):
        """Write src under app_root and run it; return (rc, out, err)."""
        f = write(app_root, name, src)
        return self.run_module(app_root, f)


@support.requires_subprocess()
class TestClassification(AppStrictTestBase):
    def test_unrestricted_by_default(self):
        # No strict root: the fork behaves exactly like upstream CPython.
        f = write(self.root, "free.py", """
            class A: pass
            class B: pass
            exec("x = 1")
            print("ok")
        """)
        rc, out, err = run_python(str(f))
        self.assertEqual(rc, 0, err)
        self.assertIn("ok", out)

    def test_rejects_two_classes(self):
        rc, out, err = self.compile_only(self.root, """
            class A: pass
            class B: pass
        """)
        self.assertNotEqual(rc, 0)
        self.assertIn("ASR001", err)

    def test_exclusion_path(self):
        app = self.root / "src"
        gen = app / "generated"
        f = write(gen, "main.py", """
            class A: pass
            class B: pass
            print("ok")
        """)
        rc, out, err = run_python(
            "--app-strict-root", str(app),
            "--app-strict-exclude", str(gen),
            str(f))
        self.assertEqual(rc, 0, err)
        self.assertIn("ok", out)

    def test_symlink_resolution(self):
        # A symlink pointing into a restricted root must be recognized.
        real = write(self.root / "src", "foo.py", """
            class A: pass
            class B: pass
        """)
        link = self.root / "link.py"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported")
        rc, out, err = run_python(
            "--app-strict-root", str(self.root / "src"), str(link))
        self.assertNotEqual(rc, 0)
        self.assertIn("ASR001", err)


@support.requires_subprocess()
class TestRules(AppStrictTestBase):
    """Table-driven: each case is (rule_id, source, should_fail)."""

    CASES = [
        # ASR001 - at most one top-level class
        ("ASR001", "class A: pass\nclass B: pass\n", True),
        ("ASR001", "class A: pass\n", False),
        # ASR002 - no nested classes
        ("ASR002", "class A:\n    class B: pass\n", True),
        ("ASR002", "def f(x: int) -> int:\n    class B: pass\n    return 1\n", True),
        # ASR003 - imports only at module level
        ("ASR003", "def f(x: int) -> int:\n    import os\n    return 1\n", True),
        ("ASR003", "import os\nX = 1\n", False),
        # ASR004 - no star imports
        ("ASR004", "from os import *\n", True),
        # ASR005 - no executable module-level control flow
        ("ASR005", "if True:\n    pass\n", True),
        ("ASR005", "for i in range(3):\n    pass\n", True),
        ("ASR005", "try:\n    pass\nexcept ValueError:\n    pass\n", True),
        # ASR010/ASR011 - no global/nonlocal
        ("ASR010", "def f(x: int) -> int:\n    global y\n    return 1\n", True),
        ("ASR011", "def f(x: int) -> int:\n    nonlocal y\n    return 1\n", True),
        # ASR012 - no mutable module-level literals
        ("ASR012", "CACHE = {}\n", True),
        ("ASR012", "ITEMS = []\n", True),
        ("ASR012", "TIMEOUT = 10\nNAME = 'x'\nFLAGS = ('a','b')\n", False),
        # ASR013 - no mutable default arguments
        ("ASR013", "def f(xs: list = []) -> None:\n    pass\n", True),
        ("ASR013", "def f(n: int = 0) -> int:\n    return n\n", False),
        # ASR020-23 - no eval/exec/compile/__import__
        ("ASR020", "def f(x: str) -> None:\n    eval(x)\n", True),
        ("ASR021", "def f(x: str) -> None:\n    exec(x)\n", True),
        ("ASR022", "def f(x: str) -> None:\n    compile(x, 'f', 'exec')\n", True),
        ("ASR023", "def f(n: str) -> None:\n    __import__(n)\n", True),
        # ASR024 - no reflection builtins
        ("ASR024", "def f(o: object) -> object:\n    return getattr(o, 'x')\n", True),
        ("ASR024", "def f(o: object) -> object:\n    return vars(o)\n", True),
        # ASR025 - no dangerous dunder attributes
        ("ASR025", "def f(o: object) -> object:\n    return o.__dict__\n", True),
        ("ASR025", "def f(o: object) -> object:\n    return o.__class__\n", True),
        # ASR030 - no introspection module imports
        ("ASR030", "import inspect\n", True),
        ("ASR030", "import ctypes\n", True),
        ("ASR030", "from importlib import reload\n", True),
        # ASR040-43 - class structure
        ("ASR040", "class A(int, str): pass\n", True),
        ("ASR040", "class A(int): pass\n", False),
        ("ASR041", "def mk() -> type:\n    return int\nclass A(mk()): pass\n", True),
        ("ASR042", "class A(metaclass=type): pass\n", True),
        # ASR050/51 - signatures
        ("ASR050", "def f(x):\n    return x\n", True),
        ("ASR050", "def f(x: int) -> int:\n    return x\n", False),
        ("ASR051", "def f(x: int):\n    return x\n", True),
        # ASR052/53 - variadics
        ("ASR052", "def f(*args: int) -> None:\n    pass\n", True),
        ("ASR053", "def f(x: int) -> int:\n    return int(*[x])\n", True),
        # ASR060/61 - nested functions and lambdas
        ("ASR060", "def f(x: int) -> int:\n    def g(y: int) -> int:\n        return y\n    return g(x)\n", True),
        ("ASR061", "def f(x: int) -> int:\n    return (lambda y: y)(x)\n", True),
        # ASR062 - no assignment expressions
        ("ASR062", "def f(x: int) -> int:\n    if (y := x):\n        return y\n    return 0\n", True),
        # ASR063 - no del
        ("ASR063", "def f(x: int) -> int:\n    del x\n    return 0\n", True),
        # ASR064/65 - no yield/yield from
        ("ASR064", "def f(x: int):\n    yield x\n", True),
        # ASR070 - no while
        ("ASR070", "def f(x: int) -> int:\n    while x > 0:\n        x -= 1\n    return x\n", True),
        # ASR072 - no bare / broad except
        ("ASR072", "def f(x: int) -> int:\n    try:\n        return x\n    except:\n        return 0\n", True),
        ("ASR072", "def f(x: int) -> int:\n    try:\n        return x\n    except Exception:\n        return 0\n", True),
        ("ASR072", "def f(x: int) -> int:\n    try:\n        return x\n    except ValueError:\n        return 0\n", False),
        # ASR090 - no typing.Any
        ("ASR090", "from typing import Any\n", True),
        ("ASR090", "def f(x: Any) -> Any:\n    return x\n", True),
        # magic methods
        ("ASR081", "class A:\n    def __getattr__(self, n: str) -> object:\n        return None\n", True),
        ("ASR081", "class A:\n    def __init__(self) -> None:\n        pass\n", False),
    ]

    def test_rules(self):
        for rule, src, should_fail in self.CASES:
            with self.subTest(rule=rule, src=src):
                rc, out, err = self.compile_only(self.root, src)
                if should_fail:
                    self.assertNotEqual(rc, 0, f"{rule} should reject:\n{src}")
                    self.assertIn(rule, err,
                                  f"expected {rule} in stderr:\n{err}")
                else:
                    self.assertEqual(rc, 0,
                                     f"{rule} should accept:\n{src}\n{err}")

    def test_syntax_error_fields(self):
        rc, out, err = self.compile_only(self.root, "class A: pass\nclass B: pass\n")
        self.assertNotEqual(rc, 0)
        self.assertIn("SyntaxError", err)
        self.assertIn("[ASR001]", err)
        # Location preserved: second class on line 2.
        self.assertIn("line 2", err)


@support.requires_subprocess()
class TestLibraryBoundary(AppStrictTestBase):
    def test_unrestricted_library(self):
        """Restricted app may import an unrestricted dynamic library."""
        lib = write(self.root / "lib", "dynamic_lib.py", """
            class Meta(type):
                pass
            class A(metaclass=Meta):
                pass
            class B:
                pass
            exec("generated = 42")
            def dynamic(x):
                return getattr(x, "foo")
        """)
        service = write(self.root / "app", "service.py", """
            import sys
            sys.path.insert(0, "../lib")
            import dynamic_lib

            class Service:
                def run(self) -> int:
                    return dynamic_lib.generated
            print(dynamic_lib.generated)
        """)
        rc, out, err = run_python(
            "--app-strict-root", str(self.root / "app"),
            str(service), cwd=str(self.root / "app"))
        self.assertEqual(rc, 0, err)
        self.assertIn("42", out)

    def test_dynamic_lib_under_root_rejected(self):
        """The same dynamic source copied under a restricted root fails."""
        write(self.root / "app", "dynamic_lib.py", """
            class Meta(type):
                pass
            class A(metaclass=Meta):
                pass
            class B:
                pass
            exec("generated = 42")
        """)
        main = write(self.root / "app", "main.py", "import dynamic_lib\n")
        rc, out, err = run_python(
            "--app-strict-root", str(self.root / "app"),
            str(main))
        self.assertNotEqual(rc, 0)
        self.assertIn("ASR", err)

    def test_callback_no_leak(self):
        """Restricted callback passed to an unrestricted library works."""
        write(self.root / "lib", "caller.py", """
            def call(f, x):
                return f(x)
        """)
        main = write(self.root / "app", "main.py", """
            import sys
            sys.path.insert(0, "../lib")
            import caller

            def f(x: int) -> int:
                return x + 1

            RESULT = caller.call(f, 1)
        """)
        # The module-level RESULT assignment is a call, so make the module
        # unrestricted... but then it isn't restricted.  Instead put the call
        # in the (unrestricted) library and import the callback from app.
        write(self.root / "lib", "runner.py", """
            from main import f
            def go() -> int:
                return f(1)
        """)
        # Simplest: run the app file which passes f into the library call
        # from inside a method (not at module level).
        write(self.root / "app", "main2.py", """
            import sys
            sys.path.insert(0, "../lib")
            import caller

            def f(x: int) -> int:
                return x + 1

            class Main:
                def run(self) -> int:
                    return caller.call(f, 1)

            if __name__ == "__main__":
                pass
        """)
        # Actually execute: use -c to invoke after import machinery is set.
        rc, out, err = run_python(
            "--app-strict-root", str(self.root / "app"),
            "-c", textwrap.dedent("""
                import sys
                sys.path.insert(0, %r)
                import main2, caller
                assert caller.call(main2.f, 1) == 2
                print("ok")
            """ % str(self.root / "app")),
            cwd=str(self.root))
        self.assertEqual(rc, 0, err)
        self.assertIn("ok", out)


@support.requires_subprocess()
class TestCodeObjectMarker(AppStrictTestBase):
    def test_co_appstrict_flag(self):
        app = write(self.root / "app", "mymod.py", """
            class A:
                def m(self) -> int:
                    return 1
        """)
        rc, out, err = run_python(
            "--app-strict-root", str(self.root / "app"),
            "-c", textwrap.dedent("""
                import sys, marshal
                sys.path.insert(0, %r)
                import mymod
                co = mymod.A.m.__code__
                assert co.co_appstrict, co.co_flags
                data = marshal.dumps(co)
                co2 = marshal.loads(data)
                assert co2.co_flags & 0x10000000, hex(co2.co_flags)
                print("ok")
            """ % str(self.root / "app")))
        self.assertEqual(rc, 0, err)
        self.assertIn("ok", out)


@support.requires_subprocess()
class TestPycIntegrity(AppStrictTestBase):
    def test_stale_unrestricted_pyc_not_accepted(self):
        """A .pyc produced in unrestricted mode must not bypass AppStrict."""
        app = self.root / "app"
        src = write(app, "bad.py", """
            class A: pass
            class B: pass
        """)
        # Step 1: compile with ordinary unrestricted CPython to make a cache.
        rc, out, err = run_python(
            "-c", f"import sys; sys.path.insert(0, {str(app)!r}); import bad")
        self.assertEqual(rc, 0, err)
        pycache = app / "__pycache__"
        self.assertTrue(pycache.is_dir(), "no pyc cache produced")
        # Step 2: restart with the path restricted and import again.
        rc, out, err = run_python(
            "--app-strict-root", str(app),
            "-c", f"import sys; sys.path.insert(0, {str(app)!r}); import bad")
        self.assertNotEqual(rc, 0)
        self.assertIn("ASR001", err)

    def test_restricted_cache_reused(self):
        """A .pyc produced in AppStrict mode must load normally."""
        app = self.root / "app"
        src = write(app, "good.py", """
            class A:
                def m(self) -> int:
                    return 7
        """)
        rc, out, err = run_python(
            "--app-strict-root", str(app),
            "-c", f"import sys; sys.path.insert(0, {str(app)!r}); import good")
        self.assertEqual(rc, 0, err)
        self.assertTrue((app / "__pycache__").is_dir())
        # Second run should use the validated cache without recompiling.
        rc, out, err = run_python(
            "--app-strict-root", str(app),
            "-c", f"import sys; sys.path.insert(0, {str(app)!r}); import good; print('ok')")
        self.assertEqual(rc, 0, err)
        self.assertIn("ok", out)


@support.requires_subprocess()
class TestAcceptedApplication(AppStrictTestBase):
    def test_spec_example(self):
        rc, out, err = self.compile_only(self.root, """
            from dataclasses import dataclass

            @dataclass
            class Employee:
                id: int
                name: str
                manager_id: int | None = None

                def rename(self, name: str) -> None:
                    self.name = name

                def managed(self) -> bool:
                    return self.manager_id is not None
        """)
        self.assertEqual(rc, 0, err)


if __name__ == "__main__":
    unittest.main()
