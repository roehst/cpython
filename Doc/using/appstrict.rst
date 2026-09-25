.. _using-appstrict:

====================================
AppStrict: restricted application Python
====================================

.. note::

   AppStrict is a fork extension and is not part of upstream CPython.

AppStrict is an optional compilation mode that restricts *application-owned*
Python source files to a statically analyzable subset of Python.  Library code
(standard library, site-packages, C extensions, frameworks) is unaffected and
runs as ordinary Python.

The goal is **not** security or sandboxing.  The goal is to reduce runtime
dynamism, metaprogramming, reflection, uncontrolled state and structural
complexity in application source so that it is easier to analyze statically,
refactor automatically, test with property-based tools, and verify.

Command-line options
--------------------

.. cmdoption:: --app-strict-root PATH

   Mark ``PATH`` as an application source root.  Python source files whose
   canonical path lies under a strict root are compiled in AppStrict mode.
   This option may be given multiple times.

.. cmdoption:: --app-strict-exclude PATH

   Exclude ``PATH`` from AppStrict mode.  This option may be given multiple
   times and takes precedence over ``--app-strict-root``.

Example::

   python --app-strict-root ./src/myapp --app-strict-exclude ./src/myapp/generated -m myapp

A source file is restricted if and only if its canonical path is under some
strict root and not under any exclusion.  Canonicalization makes the path
absolute, normalizes ``.`` / ``..``, resolves symbolic links, and uses
platform-appropriate case semantics.  Classification is based on source
*ownership/path*, never on the import name, so editable installs work.

Without any ``--app-strict-root``, the interpreter behaves exactly like
upstream CPython.  ``-c``, the REPL and C extensions are never restricted.

Library boundary
----------------

Restrictions apply when compiling each restricted module's own code object;
they do not propagate into called library code.  Restricted application code
may freely use a dynamic library such as SQLAlchemy or Pydantic::

   from sqlalchemy import select

   class EmployeeRepository:
       def find(self, db: Session, id: int) -> Employee | None:
           return db.scalar(select(Employee).where(Employee.id == id))

The library remains ordinary Python; only the application's own source is
restricted.

Diagnostics
-----------

Rejected programs raise :exc:`SyntaxError` with a stable rule identifier and a
preserved source location, for example::

   File ".../employee.py", line 17
       ...
   SyntaxError: [ASR061] lambda expressions are not permitted in application code

Rules
-----

Module structure:

* **ASR001** at most one top-level class per module
* **ASR002** no nested class definitions
* **ASR003** imports only at module level
* **ASR004** no star imports
* **ASR005** no executable module-level control flow

Global state:

* **ASR010** no ``global``
* **ASR011** no ``nonlocal``
* **ASR012** no mutable or non-constant module-level assignments
* **ASR013** no mutable default arguments

Dynamic code and reflection:

* **ASR020–ASR023** no ``eval``, ``exec``, ``compile``, ``__import__``
* **ASR024** no ``globals``/``locals``/``vars``/``getattr``/``setattr``/``delattr``
* **ASR025** no access to ``__dict__``, ``__class__``, ``__bases__``,
  ``__base__``, ``__mro__``, ``__subclasses__``, ``__code__``, ``__closure__``,
  ``__globals__``, ``__func__``, ``__self__``
* **ASR030** no importing ``inspect``, ``ctypes``, ``marshal``, ``dis``,
  ``importlib`` or ``pkgutil``

Classes:

* **ASR040** single inheritance only
* **ASR041** the base must be a statically recognizable name (generic
  subscripting such as ``Base[T]`` is allowed)
* **ASR042** no explicit metaclass
* **ASR043** no dynamic class keyword arguments

Functions:

* **ASR050** every parameter must be annotated (except ``self`` / ``cls``)
* **ASR051** every function must have a return annotation
* **ASR052** no ``*args`` / ``**kwargs`` declarations
* **ASR053** no starred call expansion
* **ASR060** no nested function definitions
* **ASR061** no ``lambda``
* **ASR062** no assignment expressions
* **ASR063** no ``del``
* **ASR064**/**ASR065** no ``yield`` / ``yield from``
* **ASR066** comprehensions may have at most one generator

Control flow and exceptions:

* **ASR070** no ``while`` loops
* **ASR071** at most 3 exception handlers per ``try``
* **ASR072** no bare ``except`` and no ``except Exception`` / ``except
  BaseException``

Other:

* **ASR080** decorators must be statically named callables
* **ASR081** defining ``__getattr__``, ``__getattribute__``, ``__setattr__``,
  ``__delattr__``, ``__new__``, ``__init_subclass__``, ``__class_getitem__``,
  ``__mro_entries__``, ``__reduce__`` or ``__reduce_ex__`` is not permitted
* **ASR090** no ``typing.Any``
* **ASR100–ASR109** complexity limits (function size, nesting, branch
  complexity, loop nesting, parameters, locals, methods, attributes, module
  size, match cases)

``.pyc`` caches
---------------

Code objects compiled from restricted modules carry the internal
``CO_APPSTRICT`` flag (exposed read-only as ``code.co_appstrict`` and
preserved by :mod:`marshal`).  A cached ``.pyc`` for a restricted source path
that lacks this marker is treated as invalid and the source is recompiled, so a
stale ordinary ``.pyc`` cannot bypass AppStrict validation.
