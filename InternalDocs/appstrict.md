# AppStrict: Statically Restricted Application Python

AppStrict is a CPython fork feature that adds a *static restriction* pass over
application-owned Python source files.  Standard-library code, site-packages,
C extensions and other dependencies are unaffected and continue to compile and
run as ordinary Python.

This is **not** a security or sandboxing feature.  It is an analyzability
feature: it reduces runtime dynamism, metaprogramming, reflection, uncontrolled
state and structural complexity in *application* source so that the application
code is easier to analyze statically, refactor, test and verify.

## Architecture

```
                    CPython runtime
                          |
        +-----------------+-----------------+
        |                                   |
  application source                   library source
        |                                   |
      parser                              parser
        |                                   |
       AST                                 AST
        |                                   |
  AppStrict validator                       |
        |                                   |
        +-----------------+-----------------+
                          |
                  normal CPython compiler
                          |
                       bytecode
                          |
                     CPython VM
```

AppStrict does not add a parser, grammar, VM, bytecode or object model.  It
reuses CPython's normal syntax, ASDL AST, compiler, bytecode and import
machinery.  The restriction is expressed as a static semantic validator that
runs on the native AST.

### Compiler insertion point

The single validation hook is in `_PyAST_Compile()` (`Python/compile.c`):

```c
if (_PyAppStrict_IsRestrictedFilename(tstate, filename)) {
    if (!_PyAppStrict_Validate(mod, filename)) {
        return NULL;
    }
}
```

Validation happens after parsing and ordinary AST validation, and before
symbol-table / code generation, so the programmer's original source structure
is checked.  Code generation itself is not modified.

### Files

* `Python/appstrict.c` — path classification + the AST validator.
* `Include/internal/pycore_appstrict.h` — internal API.
* `Python/compile.c` — single validation hook + code-tree marker.
* `Python/getopt.c`, `Python/initconfig.c` — command-line options.
* `Include/cpython/initconfig.h` — `appstrict_roots` / `appstrict_excludes`.
* `Include/cpython/code.h` — `CO_APPSTRICT`.
* `Objects/codeobject.c` — read-only `code.co_appstrict`.
* `Python/import.c` — `_imp.is_appstrict_path`.
* `Lib/importlib/_bootstrap_external.py` — pyc cache compatibility.
* `Lib/test/test_appstrict.py` — tests.

## Scope and classification

Restriction is determined **by source path ownership**, never by the call
stack or by import-name prefix.

```
python --app-strict-root ./src/myapp --app-strict-exclude ./src/myapp/generated -m myapp
```

A source file is restricted iff its canonical path lies under some strict root
and not under any exclusion.  Canonicalization:

1. makes the path absolute;
2. resolves symbolic links (via `realpath()`) and normalizes `.` / `..`;
3. uses platform-appropriate case semantics for comparison.

Editable installs (`.pth` files pointing into a source tree) work, because the
canonical source path is what is classified, not the import name.

`-c`, the REPL, `<string>`, `<stdin>`, frozen modules and C extensions are
never restricted (pseudo-filenames beginning with `<` are skipped).

## Diagnostics

Rejected programs produce a `SyntaxError` with a stable `[ASRxxx]` identifier
and preserved source location (filename, line, column, end line/column).

## Rules

| Rule    | Restriction |
|---------|-------------|
| ASR001  | At most one top-level class per module |
| ASR002  | No nested class definitions |
| ASR003  | Imports only at module level |
| ASR004  | No star imports |
| ASR005  | No executable module-level control flow |
| ASR010  | No `global` |
| ASR011  | No `nonlocal` |
| ASR012  | No mutable/non-constant module-level assignments |
| ASR013  | No mutable default arguments |
| ASR020–23 | No `eval` / `exec` / `compile` / `__import__` |
| ASR024  | No `globals`/`locals`/`vars`/`getattr`/`setattr`/`delattr` |
| ASR025  | No access to dangerous dunder attributes (`__dict__`, `__class__`, ...) |
| ASR030  | No importing `inspect`, `ctypes`, `marshal`, `dis`, `importlib`, `pkgutil` |
| ASR040  | Single inheritance only |
| ASR041  | Class base must be a statically recognizable name |
| ASR042  | No explicit metaclass |
| ASR043  | No dynamic class keyword arguments |
| ASR050  | Missing parameter type annotation |
| ASR051  | Missing return type annotation |
| ASR052  | No `*args` / `**kwargs` declarations |
| ASR053  | No starred call expansion |
| ASR060  | No nested function definitions |
| ASR061  | No lambda expressions |
| ASR062  | No assignment expressions (`:=`) |
| ASR063  | No `del` |
| ASR064  | No `yield` |
| ASR065  | No `yield from` |
| ASR066  | Comprehensions may have at most one generator |
| ASR070  | No `while` loops |
| ASR071  | Too many exception handlers (max 3) |
| ASR072  | No bare / broad `except` (`except:`, `except Exception`, `except BaseException`) |
| ASR080  | Decorators must be statically named callables |
| ASR081  | Prohibited magic-method definitions (`__getattr__`, `__setattr__`, `__new__`, ...) |
| ASR090  | No `typing.Any` |
| ASR100–109 | Complexity limits (below) |

### Complexity limits

Per function/method: max 40 statements, nesting depth 4, 10 branch points,
loop nesting 2, 8 parameters, 20 locals, 3 exception handlers, 8 match cases,
comprehension nesting 1.  Per class: max 30 methods, 30 declared attributes.
Per module: max 30 top-level functions, 1 top-level class, 2500 AST nodes.

Branch complexity (deterministic, from the AST): each of `If`, `For`,
`AsyncFor` adds one; each `match` case after the first adds one; each
`ExceptHandler` adds one; a `BoolOp` adds `len(values) - 1`; `IfExp` adds one;
each comprehension `if` filter adds one.

Nesting increases for the bodies of `if`, `for`/`async for`, `try`/`except`/
`finally`, `with`/`async with`, and `match` cases.  Function/class definitions
begin a new complexity scope.

## Code-object marker and `.pyc` integrity

Every code object compiled from a restricted module carries the
`CO_APPSTRICT` flag (`0x10000000`), propagated to the module code and all
nested code objects.  `marshal` preserves it because it is part of the normal
`co_flags`.  A read-only `code.co_appstrict` property exposes it.

When importing a restricted source path, a cached `.pyc` whose code object
lacks `CO_APPSTRICT` is treated as invalid and the source is recompiled (a
stale ordinary `.pyc` cannot silently bypass validation).  A `.pyc` produced
in AppStrict mode loads normally.

## Non-goals

AppStrict is not a sandbox and not a security boundary.  It never validates
dependency source merely because restricted code imports it.  It does not make
the whole fork a restricted dialect; ordinary dynamic Python continues to work
outside restricted roots.
