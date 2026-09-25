/* AppStrict: statically restricted application Python.

   This file implements the AppStrict compilation mode for the CPython fork.

   A source file is "restricted" iff its canonical path lies under one of the
   --app-strict-root directories and not under any --app-strict-exclude
   directory.  Restricted files are validated against a static structural
   subset of Python (the ASR rules) after parsing and ordinary AST
   validation, before symbol-table / code generation.  Rejected programs
   produce a SyntaxError carrying a stable [ASRxxx] rule identifier.

   The validator operates directly on CPython's native ASDL AST structures;
   it never materializes Python-level ast.AST objects.

   This is an analyzability restriction, not a security boundary: unrestricted
   library code called from restricted application code keeps full Python
   semantics.  See InternalDocs/appstrict.md.
*/

#include "Python.h"
#include "osdefs.h"               // SEP, ALTSEP
#include "pycore_appstrict.h"
#include "pycore_fileutils.h"     // _Py_wrealpath, _Py_abspath
#include "pycore_interp.h"        // PyInterpreterState.config
#include "pycore_pystate.h"       // _PyThreadState_GET()
#include "pycore_pyerrors.h"      // _PyErr_RaiseSyntaxError()
#include "pycore_unicodeobject.h" // _PyUnicode_EqualToASCIIString()

#include <string.h>
#include <wchar.h>

#if defined(MS_WINDOWS)
#  include <stdlib.h>             // _wcsicmp
#  define appstrict_wcscasecmp _wcsicmp
#elif defined(__APPLE__)
#  include <wchar.h>
static int
appstrict_wcscasecmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && *b) {
        wchar_t ca = towlower(*a);
        wchar_t cb = towlower(*b);
        if (ca != cb) {
            return (ca < cb) ? -1 : 1;
        }
        a++;
        b++;
    }
    return (int)(towlower(*a) - towlower(*b));
}
#else
#  define appstrict_wcscasecmp(a, b) (0)  /* unused on case-sensitive fs */
#endif

/* ------------------------------------------------------------------ */
/* Limits (spec section 25)                                            */
/* ------------------------------------------------------------------ */

#define ASR_MAX_FUNCTION_STATEMENTS   40
#define ASR_MAX_NESTING_DEPTH          4
#define ASR_MAX_BRANCH_POINTS         10
#define ASR_MAX_LOOP_NESTING           2
#define ASR_MAX_PARAMETERS             8
#define ASR_MAX_LOCALS                20
#define ASR_MAX_EXCEPT_HANDLERS        3
#define ASR_MAX_MATCH_CASES            8
#define ASR_MAX_COMPREHENSION_NESTING  1
#define ASR_MAX_METHODS               30
#define ASR_MAX_CLASS_ATTRIBUTES      30
#define ASR_MAX_MODULE_FUNCTIONS      30
#define ASR_MAX_MODULE_CLASSES         1
#define ASR_MAX_MODULE_AST_NODES    2500

/* ------------------------------------------------------------------ */
/* Validator context                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    PyObject *filename;

    /* scope tracking: >0 while inside a function/class body */
    int function_depth;
    int class_depth;

    /* control-structure nesting within the current function scope */
    int control_depth;
    int loop_depth;

    /* per-function metrics (reset on entering a function) */
    int function_statements;
    int branch_points;
    int locals;
    int parameters;
    int max_control_depth;
    int max_loop_depth;

    /* module-wide metrics */
    int module_classes;
    int module_functions;
    int module_ast_nodes;
} AppStrictContext;

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */

/* Build a SyntaxError from any AST node carrying location attributes.
   Returns 0 so callers can write "return appstrict_error(...)". */
static int
appstrict_error(AppStrictContext *ctx, int lineno, int col_offset,
                int end_lineno, int end_col_offset,
                const char *rule, const char *message)
{
    if (end_lineno <= 0) {
        end_lineno = lineno;
    }
    if (end_col_offset < 0) {
        end_col_offset = col_offset;
    }
    PyObject *msg = PyUnicode_FromFormat("[%s] %s", rule, message);
    if (msg == NULL) {
        return -1;
    }
    _PyErr_RaiseSyntaxError(msg, ctx->filename, lineno, col_offset + 1,
                            end_lineno, end_col_offset + 1);
    Py_DECREF(msg);
    return 0;
}

static int
appstrict_error_stmt(AppStrictContext *ctx, stmt_ty s,
                     const char *rule, const char *message)
{
    return appstrict_error(ctx, s->lineno, s->col_offset,
                           s->end_lineno, s->end_col_offset, rule, message);
}

static int
appstrict_error_expr(AppStrictContext *ctx, expr_ty e,
                     const char *rule, const char *message)
{
    return appstrict_error(ctx, e->lineno, e->col_offset,
                           e->end_lineno, e->end_col_offset, rule, message);
}

/* ------------------------------------------------------------------ */
/* Path classification                                                 */
/* ------------------------------------------------------------------ */

/* Canonicalize *path* into a freshly allocated wchar_t* (PyMem_RawFree it).

   1. make the path absolute;
   2. resolve symbolic links and normalize . / .. via realpath() when the
      path exists;
   3. fall back to a plain absolute, . / ..-normalized path otherwise.

   Platform case semantics: on case-insensitive filesystems (Windows, macOS
   default) the comparison lowercases the canonical path. */
static wchar_t *
appstrict_canonicalize(const wchar_t *path)
{
    wchar_t *abspath = NULL;
    if (_Py_abspath(path, &abspath) < 0) {
        return NULL;
    }
    if (abspath == NULL) {
        return NULL;
    }

#ifdef HAVE_REALPATH
    /* realpath() resolves symlinks and removes . / .. for existing paths.
       The result may be longer than the input (e.g. when a path component
       is itself a symlink), so use a MAXPATHLEN-sized buffer. */
    size_t bufsize = (size_t)MAXPATHLEN + 1;
    wchar_t *resolved = PyMem_RawMalloc(bufsize * sizeof(wchar_t));
    if (resolved != NULL) {
        wchar_t *ok = _Py_wrealpath(abspath, resolved, bufsize);
        if (ok != NULL) {
            PyMem_RawFree(abspath);
            return resolved;
        }
        PyMem_RawFree(resolved);
    }
#endif
    return abspath;
}

/* Case-fold for comparison on case-insensitive platforms. */
static int
appstrict_case_insensitive(void)
{
#ifdef MS_WINDOWS
    return 1;
#elif defined(__APPLE__)
    /* The default macOS filesystem (APFS/HFS+) is case-insensitive. */
    return 1;
#else
    return 0;
#endif
}

static int
appstrict_is_sep(wchar_t c)
{
    if (c == SEP) {
        return 1;
    }
#ifdef ALTSEP
    if (c == ALTSEP) {
        return 1;
    }
#endif
    return 0;
}

static int
appstrict_wcsncmp(const wchar_t *a, const wchar_t *b, size_t n)
{
    if (appstrict_case_insensitive()) {
#if defined(MS_WINDOWS) || defined(__APPLE__)
        for (size_t i = 0; i < n; i++) {
            wchar_t ca = towlower(a[i]);
            wchar_t cb = towlower(b[i]);
            if (ca != cb || ca == 0) {
                return (ca < cb) ? -1 : (ca > cb) ? 1 : 0;
            }
        }
        return 0;
#else
        Py_UNREACHABLE();
#endif
    }
    return wcsncmp(a, b, n);
}

/* Return 1 if *path* equals *root* or lies directly under it. */
static int
appstrict_path_under(const wchar_t *path, const wchar_t *root)
{
    size_t rlen = wcslen(root);
    /* Strip a single trailing separator from the root. */
    while (rlen > 1 && appstrict_is_sep(root[rlen - 1])) {
        rlen--;
    }

    if (appstrict_wcsncmp(path, root, rlen) != 0) {
        return 0;
    }
    if (path[rlen] == 0) {
        return 1;                       /* identical paths */
    }
    return appstrict_is_sep(path[rlen]);
}

/* Is *wfilename* (a canonical path) under any configured list entry? */
static int
appstrict_in_list(const PyWideStringList *list, const wchar_t *wfilename)
{
    for (Py_ssize_t i = 0; i < list->length; i++) {
        wchar_t *canon = appstrict_canonicalize(list->items[i]);
        if (canon == NULL) {
            continue;
        }
        int match = appstrict_path_under(wfilename, canon);
        PyMem_RawFree(canon);
        if (match) {
            return 1;
        }
    }
    return 0;
}

int
_PyAppStrict_IsRestrictedFilename(PyThreadState *tstate, PyObject *filename)
{
    PyInterpreterState *interp = tstate != NULL ? tstate->interp : NULL;
    if (interp == NULL) {
        return 0;
    }
    const PyConfig *config = &interp->config;
    if (config->appstrict_roots.length == 0) {
        return 0;                       /* AppStrict disabled */
    }
    if (!PyUnicode_Check(filename)) {
        return 0;
    }

    /* Pseudo-filenames produced by -c ("<string>"), the REPL ("<stdin>"),
       frozen modules ("<frozen ...>") and similar are not real source paths
       and must never be classified as restricted: canonicalizing them would
       resolve them relative to the current working directory. */
    Py_ssize_t flen = PyUnicode_GetLength(filename);
    if (flen > 0 && PyUnicode_READ_CHAR(filename, 0) == '<') {
        return 0;
    }

    wchar_t *wfilename = PyUnicode_AsWideCharString(filename, NULL);
    if (wfilename == NULL) {
        PyErr_Clear();
        return 0;
    }

    wchar_t *canon = appstrict_canonicalize(wfilename);
    PyMem_Free(wfilename);   /* PyUnicode_AsWideCharString uses PyMem */

    if (canon == NULL) {
        return 0;
    }

    int restricted = appstrict_in_list(&config->appstrict_roots, canon);
    if (restricted) {
        int excluded = appstrict_in_list(&config->appstrict_excludes, canon);
        if (excluded) {
            restricted = 0;
        }
    }
    PyMem_RawFree(canon);
    return restricted;
}

/* ------------------------------------------------------------------ */
/* Name tables                                                         */
/* ------------------------------------------------------------------ */

static int
name_in(const char *name, const char *const *table, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(name, table[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Section 11: dynamic code generation builtins */
static const char *const ASR_DYNAMIC_BUILTINS[] = {
    "eval", "exec", "compile", "__import__",
};
/* Section 12: reflection / namespace mutation builtins */
static const char *const ASR_REFLECT_BUILTINS[] = {
    "globals", "locals", "vars", "getattr", "setattr", "delattr",
};
/* Section 12: dangerous dunder attributes */
static const char *const ASR_DUNDER_ATTRS[] = {
    "__dict__", "__class__", "__bases__", "__base__", "__mro__",
    "__subclasses__", "__code__", "__closure__", "__globals__",
    "__func__", "__self__",
};
/* Section 13: dangerous introspection modules */
static const char *const ASR_FORBIDDEN_MODULES[] = {
    "inspect", "ctypes", "marshal", "dis", "importlib", "pkgutil",
};
/* Section 15: prohibited magic method definitions */
static const char *const ASR_FORBIDDEN_MAGIC[] = {
    "__getattr__", "__getattribute__", "__setattr__", "__delattr__",
    "__new__", "__init_subclass__", "__class_getitem__", "__mro_entries__",
    "__reduce__", "__reduce_ex__",
};

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

static int appstrict_validate_stmt(AppStrictContext *ctx, stmt_ty s);
static int appstrict_validate_expr(AppStrictContext *ctx, expr_ty e);

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int
name_eq(PyObject *id, const char *s)
{
    return id != NULL && _PyUnicode_EqualToASCIIString(id, s);
}

/* Is this expression a bare Name or a (possibly generic-subscripted)
   Name / attribute chain, suitable for a class base or decorator root? */
static int
appstrict_static_name(expr_ty e)
{
    switch (e->kind) {
    case Name_kind:
        return 1;
    case Attribute_kind:
        return appstrict_static_name(e->v.Attribute.value);
    case Subscript_kind:
        /* Allow generic bases such as Base[T] (section 14). */
        return appstrict_static_name(e->v.Subscript.value);
    default:
        return 0;
    }
}

/* Is this expression a constant suitable for a module-level immutable
   assignment (section 10, ASR012)? */
static int
appstrict_is_constant_expr(expr_ty e)
{
    switch (e->kind) {
    case Constant_kind: {
        PyObject *v = e->v.Constant.value;
        return (v == Py_None || v == Py_True || v == Py_False
                || PyLong_Check(v) || PyFloat_Check(v)
                || PyComplex_Check(v) || PyUnicode_Check(v)
                || PyBytes_Check(v));
    }
    case Tuple_kind: {
        asdl_expr_seq *elts = e->v.Tuple.elts;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(elts); i++) {
            if (!appstrict_is_constant_expr(asdl_seq_GET(elts, i))) {
                return 0;
            }
        }
        return 1;
    }
    case UnaryOp_kind: {
        /* unary arithmetic over numeric constants */
        unaryop_ty op = e->v.UnaryOp.op;
        if (op != UAdd && op != USub && op != Invert) {
            return 0;
        }
        expr_ty operand = e->v.UnaryOp.operand;
        if (operand->kind != Constant_kind) {
            return 0;
        }
        PyObject *v = operand->v.Constant.value;
        return PyLong_Check(v) || PyFloat_Check(v) || PyComplex_Check(v);
    }
    case BinOp_kind: {
        /* Permit simple arithmetic over constants, e.g. 1 << 3 or 2**8. */
        operator_ty op = e->v.BinOp.op;
        if (op == MatMult) {
            return 0;
        }
        return appstrict_is_constant_expr(e->v.BinOp.left)
               && appstrict_is_constant_expr(e->v.BinOp.right);
    }
    case Call_kind:
        /* Optionally support frozenset(...) of constant arguments. */
        if (e->v.Call.func->kind == Name_kind
            && name_eq(e->v.Call.func->v.Name.id, "frozenset")
            && asdl_seq_LEN(e->v.Call.keywords) == 0)
        {
            asdl_expr_seq *args = e->v.Call.args;
            for (Py_ssize_t i = 0; i < asdl_seq_LEN(args); i++) {
                if (!appstrict_is_constant_expr(asdl_seq_GET(args, i))) {
                    return 0;
                }
            }
            return 1;
        }
        return 0;
    default:
        return 0;
    }
}

/* Is this annotation the prohibited typing.Any / bare Any name?
   Only reject when syntactically identifiable (section 29). */
static int
appstrict_annotation_is_any(expr_ty e)
{
    if (e->kind == Name_kind && name_eq(e->v.Name.id, "Any")) {
        return 1;
    }
    if (e->kind == Attribute_kind
        && name_eq(e->v.Attribute.attr, "Any")
        && e->v.Attribute.value->kind == Name_kind
        && name_eq(e->v.Attribute.value->v.Name.id, "typing"))
    {
        return 1;
    }
    return 0;
}

/* Collect the names bound by an assignment target (for the locals count). */
static void
appstrict_count_target_locals(AppStrictContext *ctx, expr_ty target)
{
    switch (target->kind) {
    case Name_kind:
        ctx->locals++;
        break;
    case Tuple_kind:
    case List_kind: {
        asdl_expr_seq *elts = target->kind == Tuple_kind
                              ? target->v.Tuple.elts : target->v.List.elts;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(elts); i++) {
            appstrict_count_target_locals(ctx, asdl_seq_GET(elts, i));
        }
        break;
    }
    case Starred_kind:
        appstrict_count_target_locals(ctx, target->v.Starred.value);
        break;
    default:
        break;
    }
}

/* Count statements recursively inside a function body (spec 25: "max AST
   statements" per function).  Nested functions/classes start their own
   scope and are not counted here. */
static int
appstrict_count_stmts(asdl_stmt_seq *body, int depth)
{
    if (depth > 64) {
        return 0;                       /* safety valve */
    }
    int total = 0;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(body); i++) {
        stmt_ty s = asdl_seq_GET(body, i);
        total++;
        switch (s->kind) {
        case If_kind:
            total += appstrict_count_stmts(s->v.If.body, depth + 1);
            total += appstrict_count_stmts(s->v.If.orelse, depth + 1);
            break;
        case For_kind:
            total += appstrict_count_stmts(s->v.For.body, depth + 1);
            total += appstrict_count_stmts(s->v.For.orelse, depth + 1);
            break;
        case AsyncFor_kind:
            total += appstrict_count_stmts(s->v.AsyncFor.body, depth + 1);
            total += appstrict_count_stmts(s->v.AsyncFor.orelse, depth + 1);
            break;
        case While_kind:
            total += appstrict_count_stmts(s->v.While.body, depth + 1);
            total += appstrict_count_stmts(s->v.While.orelse, depth + 1);
            break;
        case With_kind:
            total += appstrict_count_stmts(s->v.With.body, depth + 1);
            break;
        case AsyncWith_kind:
            total += appstrict_count_stmts(s->v.AsyncWith.body, depth + 1);
            break;
        case Try_kind:
        case TryStar_kind: {
            asdl_stmt_seq *tbody = s->kind == Try_kind
                                   ? s->v.Try.body : s->v.TryStar.body;
            asdl_excepthandler_seq *handlers = s->kind == Try_kind
                                 ? s->v.Try.handlers : s->v.TryStar.handlers;
            asdl_stmt_seq *orelse = s->kind == Try_kind
                                    ? s->v.Try.orelse : s->v.TryStar.orelse;
            asdl_stmt_seq *final = s->kind == Try_kind
                                   ? s->v.Try.finalbody : s->v.TryStar.finalbody;
            total += appstrict_count_stmts(tbody, depth + 1);
            total += appstrict_count_stmts(orelse, depth + 1);
            total += appstrict_count_stmts(final, depth + 1);
            for (Py_ssize_t j = 0; j < asdl_seq_LEN(handlers); j++) {
                excepthandler_ty h = asdl_seq_GET(handlers, j);
                total += appstrict_count_stmts(h->v.ExceptHandler.body,
                                               depth + 1);
            }
            break;
        }
        case Match_kind:
            for (Py_ssize_t j = 0; j < asdl_seq_LEN(s->v.Match.cases); j++) {
                match_case_ty mc = asdl_seq_GET(s->v.Match.cases, j);
                total += appstrict_count_stmts(mc->body, depth + 1);
            }
            break;
        default:
            break;
        }
    }
    return total;
}

/* ------------------------------------------------------------------ */
/* Decorators (section 24)                                             */
/* ------------------------------------------------------------------ */

static int
appstrict_validate_decorator(AppStrictContext *ctx, expr_ty deco)
{
    ctx->module_ast_nodes++;
    /* Valid roots: Name, Attribute chain, or a Call whose callee is a
       Name / Attribute chain. */
    expr_ty root = deco;
    if (root->kind == Call_kind) {
        root = root->v.Call.func;
    }
    if (!appstrict_static_name(root) || root->kind == Subscript_kind) {
        return appstrict_error_expr(
            ctx, deco, "ASR080",
            "decorator expression must be a statically named callable");
    }
    /* The arguments to decorator calls remain ordinary expressions. */
    if (deco->kind == Call_kind) {
        asdl_expr_seq *args = deco->v.Call.args;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(args); i++) {
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(args, i))) {
                return 0;
            }
        }
        asdl_keyword_seq *kw = deco->v.Call.keywords;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(kw); i++) {
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(kw, i)->value)) {
                return 0;
            }
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Imports (sections 9, 13, 29, 30)                                    */
/* ------------------------------------------------------------------ */

static int
appstrict_validate_import(AppStrictContext *ctx, stmt_ty s)
{
    if (ctx->function_depth > 0 || ctx->class_depth > 0) {
        return appstrict_error_stmt(
            ctx, s, "ASR003",
            "imports are only permitted at module level");
    }

    if (s->kind == Import_kind) {
        asdl_alias_seq *names = s->v.Import.names;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(names); i++) {
            alias_ty a = asdl_seq_GET(names, i);
            const char *mod = PyUnicode_AsUTF8(a->name);
            if (mod == NULL) {
                return 0;
            }
            /* top-level component decides the forbidden-module category */
            char top[64];
            const char *dot = strchr(mod, '.');
            size_t n = dot ? (size_t)(dot - mod) : strlen(mod);
            if (n >= sizeof(top)) {
                n = sizeof(top) - 1;
            }
            memcpy(top, mod, n);
            top[n] = 0;
            if (name_in(top, ASR_FORBIDDEN_MODULES,
                        Py_ARRAY_LENGTH(ASR_FORBIDDEN_MODULES))) {
                return appstrict_error_stmt(
                    ctx, s, "ASR030",
                    "importing introspection/import machinery modules is not "
                    "permitted in application code");
            }
        }
        return 1;
    }

    /* ImportFrom */
    asdl_alias_seq *names = s->v.ImportFrom.names;
    PyObject *modname = s->v.ImportFrom.module;
    const char *mod = modname ? PyUnicode_AsUTF8(modname) : NULL;
    if (modname && mod == NULL) {
        return 0;
    }

    for (Py_ssize_t i = 0; i < asdl_seq_LEN(names); i++) {
        alias_ty a = asdl_seq_GET(names, i);
        const char *nm = PyUnicode_AsUTF8(a->name);
        if (nm == NULL) {
            return 0;
        }
        if (strcmp(nm, "*") == 0) {
            return appstrict_error_stmt(
                ctx, s, "ASR004", "star imports are not permitted");
        }
        /* Section 11: reject `from builtins import eval/exec/...` */
        if (mod != NULL && strcmp(mod, "builtins") == 0
            && (name_in(nm, ASR_DYNAMIC_BUILTINS,
                        Py_ARRAY_LENGTH(ASR_DYNAMIC_BUILTINS))
                || name_in(nm, ASR_REFLECT_BUILTINS,
                           Py_ARRAY_LENGTH(ASR_REFLECT_BUILTINS)))) {
            return appstrict_error_stmt(
                ctx, s, "ASR020",
                "importing dynamic/reflection builtins is not permitted");
        }
        /* Section 29: reject `from typing import Any` */
        if (mod != NULL && strcmp(mod, "typing") == 0
            && strcmp(nm, "Any") == 0) {
            return appstrict_error_stmt(
                ctx, s, "ASR090",
                "typing.Any is not permitted in application code");
        }
    }

    if (mod != NULL) {
        char top[64];
        const char *dot = strchr(mod, '.');
        size_t n = dot ? (size_t)(dot - mod) : strlen(mod);
        if (n >= sizeof(top)) {
            n = sizeof(top) - 1;
        }
        memcpy(top, mod, n);
        top[n] = 0;
        if (name_in(top, ASR_FORBIDDEN_MODULES,
                    Py_ARRAY_LENGTH(ASR_FORBIDDEN_MODULES))) {
            return appstrict_error_stmt(
                ctx, s, "ASR030",
                "importing introspection/import machinery modules is not "
                "permitted in application code");
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Function signatures (sections 16, 17)                               */
/* ------------------------------------------------------------------ */

static int
appstrict_check_arg_annotation(AppStrictContext *ctx, arg_ty a, int is_self)
{
    if (a->annotation == NULL) {
        if (is_self) {
            return 1;                   /* self / cls need not be annotated */
        }
        return appstrict_error(ctx, a->lineno, a->col_offset,
                               a->end_lineno, a->end_col_offset,
                               "ASR050",
                               "missing parameter type annotation");
    }
    if (appstrict_annotation_is_any(a->annotation)) {
        return appstrict_error(ctx, a->lineno, a->col_offset,
                               a->end_lineno, a->end_col_offset,
                               "ASR090",
                               "typing.Any is not permitted in application code");
    }
    return 1;
}

static int
appstrict_validate_arguments(AppStrictContext *ctx, stmt_ty func,
                             arguments_ty args, int in_class)
{
    int nparams = 0;

    /* No *args / **kwargs (section 17). */
    if (args->vararg != NULL) {
        return appstrict_error_stmt(
            ctx, func, "ASR052",
            "variadic *args declarations are not permitted");
    }
    if (args->kwarg != NULL) {
        return appstrict_error_stmt(
            ctx, func, "ASR052",
            "variadic **kwargs declarations are not permitted");
    }

    asdl_arg_seq *pos = args->posonlyargs;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(pos); i++) {
        int is_self = in_class && ctx->class_depth > 0 && nparams == 0;
        arg_ty a = asdl_seq_GET(pos, i);
        const char *nm = PyUnicode_AsUTF8(a->arg);
        if (is_self && nm && (strcmp(nm, "self") == 0 || strcmp(nm, "cls") == 0)) {
            nparams++;
            continue;
        }
        if (!appstrict_check_arg_annotation(ctx, a, 0)) {
            return 0;
        }
        nparams++;
    }
    asdl_arg_seq *plain = args->args;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(plain); i++) {
        int is_self = in_class && nparams == 0;
        arg_ty a = asdl_seq_GET(plain, i);
        const char *nm = PyUnicode_AsUTF8(a->arg);
        if (is_self && nm && (strcmp(nm, "self") == 0 || strcmp(nm, "cls") == 0)) {
            nparams++;
            continue;
        }
        if (!appstrict_check_arg_annotation(ctx, a, 0)) {
            return 0;
        }
        nparams++;
    }
    asdl_arg_seq *kwo = args->kwonlyargs;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(kwo); i++) {
        if (!appstrict_check_arg_annotation(ctx, asdl_seq_GET(kwo, i), 0)) {
            return 0;
        }
        nparams++;
    }

    ctx->parameters += nparams;
    if (nparams > ASR_MAX_PARAMETERS) {
        return appstrict_error_stmt(
            ctx, func, "ASR104",
            "too many parameters (limit 8)");
    }

    /* No mutable default arguments (ASR013). */
    asdl_expr_seq *defaults = args->defaults;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(defaults); i++) {
        expr_ty d = asdl_seq_GET(defaults, i);
        if (d->kind == List_kind || d->kind == Dict_kind || d->kind == Set_kind) {
            return appstrict_error_expr(
                ctx, d, "ASR013",
                "mutable default arguments are not permitted");
        }
        if (d->kind == Call_kind
            && d->v.Call.func->kind == Name_kind
            && (name_eq(d->v.Call.func->v.Name.id, "list")
                || name_eq(d->v.Call.func->v.Name.id, "dict")
                || name_eq(d->v.Call.func->v.Name.id, "set"))) {
            return appstrict_error_expr(
                ctx, d, "ASR013",
                "mutable default arguments are not permitted");
        }
    }
    asdl_expr_seq *kw_defaults = args->kw_defaults;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(kw_defaults); i++) {
        expr_ty d = asdl_seq_GET(kw_defaults, i);
        if (d == NULL) {
            continue;
        }
        if (d->kind == List_kind || d->kind == Dict_kind || d->kind == Set_kind) {
            return appstrict_error_expr(
                ctx, d, "ASR013",
                "mutable default arguments are not permitted");
        }
    }

    /* Return annotation (ASR051). */
    expr_ty returns = func->kind == FunctionDef_kind
                      ? func->v.FunctionDef.returns
                      : func->v.AsyncFunctionDef.returns;
    if (returns == NULL) {
        return appstrict_error_stmt(
            ctx, func, "ASR051",
            "missing return type annotation");
    }
    if (appstrict_annotation_is_any(returns)) {
        return appstrict_error_stmt(
            ctx, func, "ASR051",
            "missing return type annotation (typing.Any is not permitted)");
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Function / class measurement + validation                           */
/* ------------------------------------------------------------------ */

static int appstrict_validate_stmts(AppStrictContext *ctx, asdl_stmt_seq *body);

static int
appstrict_validate_function(AppStrictContext *ctx, stmt_ty func)
{
    /* Nested functions are prohibited (ASR060).  Methods (functions
       directly inside a class body) are allowed. */
    if (ctx->function_depth > 0) {
        return appstrict_error_stmt(
            ctx, func, "ASR060",
            "nested function definitions are not permitted");
    }

    const char *name = PyUnicode_AsUTF8(
        func->kind == FunctionDef_kind ? func->v.FunctionDef.name
                                       : func->v.AsyncFunctionDef.name);
    if (name != NULL && ctx->class_depth > 0
        && name_in(name, ASR_FORBIDDEN_MAGIC,
                   Py_ARRAY_LENGTH(ASR_FORBIDDEN_MAGIC))) {
        return appstrict_error_stmt(
            ctx, func, "ASR081",
            "defining this magic method is not permitted in application code");
    }

    arguments_ty args = func->kind == FunctionDef_kind
                        ? func->v.FunctionDef.args
                        : func->v.AsyncFunctionDef.args;
    asdl_stmt_seq *body = func->kind == FunctionDef_kind
                          ? func->v.FunctionDef.body
                          : func->v.AsyncFunctionDef.body;
    asdl_expr_seq *decs = func->kind == FunctionDef_kind
                          ? func->v.FunctionDef.decorator_list
                          : func->v.AsyncFunctionDef.decorator_list;

    for (Py_ssize_t i = 0; i < asdl_seq_LEN(decs); i++) {
        if (!appstrict_validate_decorator(ctx, asdl_seq_GET(decs, i))) {
            return 0;
        }
    }

    /* Start a fresh metric scope for this function. */
    int saved_function_statements = ctx->function_statements;
    int saved_branch_points = ctx->branch_points;
    int saved_locals = ctx->locals;
    int saved_parameters = ctx->parameters;
    int saved_control_depth = ctx->control_depth;
    int saved_loop_depth = ctx->loop_depth;
    int saved_max_control = ctx->max_control_depth;
    int saved_max_loop = ctx->max_loop_depth;

    ctx->function_statements = 0;
    ctx->branch_points = 0;
    ctx->locals = 0;
    ctx->parameters = 0;
    ctx->control_depth = 0;
    ctx->loop_depth = 0;
    ctx->max_control_depth = 0;
    ctx->max_loop_depth = 0;

    int ok = appstrict_validate_arguments(ctx, func, args,
                                          ctx->class_depth > 0);
    if (ok) {
        ctx->function_depth++;
        ok = appstrict_validate_stmts(ctx, body);
        ctx->function_depth--;
    }

    /* Metric limits. */
    if (ok) {
        int total_stmts = appstrict_count_stmts(body, 0);
        if (total_stmts > ASR_MAX_FUNCTION_STATEMENTS) {
            ok = appstrict_error_stmt(ctx, func, "ASR100",
                                      "function is too large");
        }
    }
    if (ok && ctx->max_control_depth > ASR_MAX_NESTING_DEPTH) {
        ok = appstrict_error_stmt(ctx, func, "ASR101",
                                  "excessive control nesting depth");
    }
    if (ok && ctx->branch_points > ASR_MAX_BRANCH_POINTS) {
        ok = appstrict_error_stmt(ctx, func, "ASR102",
                                  "excessive branch complexity");
    }
    if (ok && ctx->max_loop_depth > ASR_MAX_LOOP_NESTING) {
        ok = appstrict_error_stmt(ctx, func, "ASR103",
                                  "excessive loop nesting");
    }
    if (ok && ctx->locals > ASR_MAX_LOCALS) {
        ok = appstrict_error_stmt(ctx, func, "ASR105",
                                  "too many local variables");
    }

    ctx->function_statements = saved_function_statements;
    ctx->branch_points = saved_branch_points;
    ctx->locals = saved_locals;
    ctx->parameters = saved_parameters;
    ctx->control_depth = saved_control_depth;
    ctx->loop_depth = saved_loop_depth;
    ctx->max_control_depth = saved_max_control;
    ctx->max_loop_depth = saved_max_loop;

    if (ok) {
        ctx->module_functions++;
        if (ctx->class_depth == 0
            && ctx->module_functions > ASR_MAX_MODULE_FUNCTIONS) {
            return appstrict_error_stmt(ctx, func, "ASR108",
                                        "module is too large");
        }
    }
    return ok;
}

static int
appstrict_validate_class(AppStrictContext *ctx, stmt_ty cls)
{
    if (ctx->class_depth > 0 || ctx->function_depth > 0) {
        return appstrict_error_stmt(
            ctx, cls, "ASR002",
            "nested class definitions are not permitted");
    }

    asdl_expr_seq *bases = cls->v.ClassDef.bases;
    asdl_keyword_seq *keywords = cls->v.ClassDef.keywords;
    asdl_stmt_seq *body = cls->v.ClassDef.body;
    asdl_expr_seq *decs = cls->v.ClassDef.decorator_list;

    if (asdl_seq_LEN(bases) > 1) {
        return appstrict_error_stmt(
            ctx, cls, "ASR040",
            "multiple inheritance is not permitted in application code");
    }
    if (asdl_seq_LEN(bases) == 1) {
        expr_ty base = asdl_seq_GET(bases, 0);
        if (!appstrict_static_name(base)) {
            return appstrict_error_stmt(
                ctx, cls, "ASR041",
                "class base must be a statically recognizable name");
        }
    }
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(keywords); i++) {
        keyword_ty kw = asdl_seq_GET(keywords, i);
        if (kw->arg != NULL && name_eq(kw->arg, "metaclass")) {
            return appstrict_error_stmt(
                ctx, cls, "ASR042",
                "explicit metaclasses are not permitted");
        }
        return appstrict_error_stmt(
            ctx, cls, "ASR043",
            "dynamic class keyword arguments are not permitted");
    }
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(decs); i++) {
        if (!appstrict_validate_decorator(ctx, asdl_seq_GET(decs, i))) {
            return 0;
        }
    }

    ctx->module_classes++;
    if (ctx->module_classes > ASR_MAX_MODULE_CLASSES) {
        return appstrict_error_stmt(
            ctx, cls, "ASR001",
            "at most one top-level class is permitted per module");
    }

    int methods = 0;
    int attrs = 0;
    ctx->class_depth++;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(body); i++) {
        stmt_ty s = asdl_seq_GET(body, i);
        switch (s->kind) {
        case FunctionDef_kind:
        case AsyncFunctionDef_kind:
            methods++;
            break;
        case AnnAssign_kind:
        case Assign_kind:
            attrs++;
            break;
        default:
            break;
        }
        if (!appstrict_validate_stmt(ctx, s)) {
            ctx->class_depth--;
            return 0;
        }
    }
    ctx->class_depth--;

    if (methods > ASR_MAX_METHODS) {
        return appstrict_error_stmt(ctx, cls, "ASR106",
                                    "too many methods");
    }
    if (attrs > ASR_MAX_CLASS_ATTRIBUTES) {
        return appstrict_error_stmt(ctx, cls, "ASR107",
                                    "too many declared attributes");
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Statements                                                          */
/* ------------------------------------------------------------------ */

/* Enter a nested control structure, tracking nesting/loop depth and branch
   points.  Returns 0 with an error set if a hard limit is exceeded. */
static int
appstrict_enter_control(AppStrictContext *ctx, stmt_ty s, int is_loop)
{
    if (ctx->function_depth > 0) {
        ctx->branch_points++;
        ctx->control_depth++;
        if (is_loop) {
            ctx->loop_depth++;
        }
        if (ctx->control_depth > ctx->max_control_depth) {
            ctx->max_control_depth = ctx->control_depth;
        }
        if (ctx->loop_depth > ctx->max_loop_depth) {
            ctx->max_loop_depth = ctx->loop_depth;
        }
    }
    return 1;
}

static void
appstrict_leave_control(AppStrictContext *ctx, int is_loop)
{
    if (ctx->function_depth > 0) {
        ctx->control_depth--;
        if (is_loop) {
            ctx->loop_depth--;
        }
    }
}

static int
appstrict_validate_stmts(AppStrictContext *ctx, asdl_stmt_seq *body)
{
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(body); i++) {
        if (!appstrict_validate_stmt(ctx, asdl_seq_GET(body, i))) {
            return 0;
        }
    }
    return 1;
}

/* Module scope whitelist (ASR005). */
static int
appstrict_module_stmt_allowed(stmt_ty s)
{
    switch (s->kind) {
    case Expr_kind:
        /* docstring only: a bare string constant */
        return s->v.Expr.value->kind == Constant_kind
               && PyUnicode_Check(s->v.Expr.value->v.Constant.value);
    case Import_kind:
    case ImportFrom_kind:
    case FunctionDef_kind:
    case AsyncFunctionDef_kind:
    case ClassDef_kind:
    case AnnAssign_kind:
    case Assign_kind:
    case TypeAlias_kind:
    case Pass_kind:
        return 1;
    default:
        return 0;
    }
}

static int
appstrict_validate_assign_common(AppStrictContext *ctx, stmt_ty s,
                                 expr_ty target, expr_ty value)
{
    /* Module-level: only simple constant assignments (ASR012). */
    if (ctx->function_depth == 0 && ctx->class_depth == 0) {
        if (target != NULL && target->kind != Name_kind) {
            return appstrict_error_stmt(
                ctx, s, "ASR012",
                "module-level assignment must bind a plain name");
        }
        if (value != NULL && !appstrict_is_constant_expr(value)) {
            return appstrict_error_stmt(
                ctx, s, "ASR012",
                "mutable or non-constant module-level assignments are not "
                "permitted");
        }
    }
    else if (ctx->function_depth > 0 && target != NULL) {
        appstrict_count_target_locals(ctx, target);
    }
    return 1;
}

static int
appstrict_validate_stmt(AppStrictContext *ctx, stmt_ty s)
{
    ctx->module_ast_nodes++;
    if (ctx->module_ast_nodes > ASR_MAX_MODULE_AST_NODES) {
        return appstrict_error_stmt(ctx, s, "ASR108", "module is too large");
    }

    int at_module = (ctx->function_depth == 0 && ctx->class_depth == 0);

    switch (s->kind) {
    case Import_kind:
    case ImportFrom_kind:
        return appstrict_validate_import(ctx, s);

    case FunctionDef_kind:
    case AsyncFunctionDef_kind:
        return appstrict_validate_function(ctx, s);

    case ClassDef_kind:
        return appstrict_validate_class(ctx, s);

    case Global_kind:
        return appstrict_error_stmt(ctx, s, "ASR010",
                                    "global statements are not permitted");

    case Nonlocal_kind:
        return appstrict_error_stmt(ctx, s, "ASR011",
                                    "nonlocal statements are not permitted");

    case Delete_kind:
        return appstrict_error_stmt(ctx, s, "ASR063",
                                    "del statements are not permitted");

    case While_kind:
        return appstrict_error_stmt(
            ctx, s, "ASR070",
            "while loops are not permitted in application code");

    case If_kind:
        if (at_module) {
            return appstrict_error_stmt(
                ctx, s, "ASR005",
                "executable module-level control flow is not permitted");
        }
        if (!appstrict_enter_control(ctx, s, 0)) {
            return 0;
        }
        if (!appstrict_validate_expr(ctx, s->v.If.test)
            || !appstrict_validate_stmts(ctx, s->v.If.body)
            || !appstrict_validate_stmts(ctx, s->v.If.orelse)) {
            return 0;
        }
        appstrict_leave_control(ctx, 0);
        return 1;

    case For_kind:
    case AsyncFor_kind: {
        if (at_module) {
            return appstrict_error_stmt(
                ctx, s, "ASR005",
                "executable module-level control flow is not permitted");
        }
        if (!appstrict_enter_control(ctx, s, 1)) {
            return 0;
        }
        asdl_stmt_seq *body = s->kind == For_kind
                              ? s->v.For.body : s->v.AsyncFor.body;
        asdl_stmt_seq *orelse = s->kind == For_kind
                                ? s->v.For.orelse : s->v.AsyncFor.orelse;
        expr_ty iter = s->kind == For_kind
                       ? s->v.For.iter : s->v.AsyncFor.iter;
        expr_ty target = s->kind == For_kind
                         ? s->v.For.target : s->v.AsyncFor.target;
        if (ctx->function_depth > 0) {
            appstrict_count_target_locals(ctx, target);
        }
        if (!appstrict_validate_expr(ctx, iter)
            || !appstrict_validate_stmts(ctx, body)
            || !appstrict_validate_stmts(ctx, orelse)) {
            return 0;
        }
        appstrict_leave_control(ctx, 1);
        return 1;
    }

    case With_kind:
    case AsyncWith_kind: {
        if (at_module) {
            return appstrict_error_stmt(
                ctx, s, "ASR005",
                "executable module-level control flow is not permitted");
        }
        if (!appstrict_enter_control(ctx, s, 0)) {
            return 0;
        }
        asdl_withitem_seq *items = s->kind == With_kind
                                   ? s->v.With.items : s->v.AsyncWith.items;
        asdl_stmt_seq *body = s->kind == With_kind
                              ? s->v.With.body : s->v.AsyncWith.body;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(items); i++) {
            withitem_ty it = asdl_seq_GET(items, i);
            if (!appstrict_validate_expr(ctx, it->context_expr)) {
                return 0;
            }
            if (it->optional_vars != NULL && ctx->function_depth > 0) {
                appstrict_count_target_locals(ctx, it->optional_vars);
            }
        }
        if (!appstrict_validate_stmts(ctx, body)) {
            return 0;
        }
        appstrict_leave_control(ctx, 0);
        return 1;
    }

    case Try_kind:
    case TryStar_kind: {
        if (at_module) {
            return appstrict_error_stmt(
                ctx, s, "ASR005",
                "executable module-level control flow is not permitted");
        }
        asdl_excepthandler_seq *handlers =
            s->kind == Try_kind ? s->v.Try.handlers : s->v.TryStar.handlers;
        asdl_stmt_seq *body =
            s->kind == Try_kind ? s->v.Try.body : s->v.TryStar.body;
        asdl_stmt_seq *orelse =
            s->kind == Try_kind ? s->v.Try.orelse : s->v.TryStar.orelse;
        asdl_stmt_seq *finalbody =
            s->kind == Try_kind ? s->v.Try.finalbody : s->v.TryStar.finalbody;

        int nhandlers = asdl_seq_LEN(handlers);
        if (nhandlers > ASR_MAX_EXCEPT_HANDLERS) {
            return appstrict_error_stmt(
                ctx, s, "ASR071",
                "too many exception handlers (maximum 3)");
        }
        if (!appstrict_enter_control(ctx, s, 0)) {
            return 0;
        }
        for (Py_ssize_t i = 0; i < nhandlers; i++) {
            excepthandler_ty h = asdl_seq_GET(handlers, i);
            /* Reject bare / broad exception handlers (section 23). */
            if (h->v.ExceptHandler.type == NULL) {
                return appstrict_error(
                    ctx, h->lineno, h->col_offset,
                    h->end_lineno, h->end_col_offset, "ASR072",
                    "bare except handlers are not permitted");
            }
            expr_ty htype = h->v.ExceptHandler.type;
            if (htype->kind == Name_kind
                && (name_eq(htype->v.Name.id, "BaseException")
                    || name_eq(htype->v.Name.id, "Exception"))) {
                return appstrict_error(
                    ctx, h->lineno, h->col_offset,
                    h->end_lineno, h->end_col_offset, "ASR072",
                    "catching Exception or BaseException is not permitted");
            }
            if (!appstrict_validate_expr(ctx, htype)
                || !appstrict_validate_stmts(ctx, h->v.ExceptHandler.body)) {
                return 0;
            }
        }
        if (!appstrict_validate_stmts(ctx, body)
            || !appstrict_validate_stmts(ctx, orelse)
            || !appstrict_validate_stmts(ctx, finalbody)) {
            return 0;
        }
        appstrict_leave_control(ctx, 0);
        return 1;
    }

    case Match_kind: {
        if (at_module) {
            return appstrict_error_stmt(
                ctx, s, "ASR005",
                "executable module-level control flow is not permitted");
        }
        asdl_match_case_seq *cases = s->v.Match.cases;
        int ncases = asdl_seq_LEN(cases);
        if (ncases > ASR_MAX_MATCH_CASES) {
            return appstrict_error_stmt(
                ctx, s, "ASR109",
                "too many match cases");
        }
        if (!appstrict_enter_control(ctx, s, 0)) {
            return 0;
        }
        if (ctx->function_depth > 0 && ncases > 1) {
            /* each Match case after the first adds one branch point */
            ctx->branch_points += ncases - 1;
        }
        if (!appstrict_validate_expr(ctx, s->v.Match.subject)) {
            return 0;
        }
        for (Py_ssize_t i = 0; i < ncases; i++) {
            match_case_ty mc = asdl_seq_GET(cases, i);
            if (mc->guard != NULL
                && !appstrict_validate_expr(ctx, mc->guard)) {
                return 0;
            }
            if (!appstrict_validate_stmts(ctx, mc->body)) {
                return 0;
            }
        }
        appstrict_leave_control(ctx, 0);
        return 1;
    }

    case Raise_kind:
        if (at_module) {
            return appstrict_error_stmt(
                ctx, s, "ASR005",
                "executable module-level control flow is not permitted");
        }
        if (s->v.Raise.exc != NULL
            && !appstrict_validate_expr(ctx, s->v.Raise.exc)) {
            return 0;
        }
        if (s->v.Raise.cause != NULL
            && !appstrict_validate_expr(ctx, s->v.Raise.cause)) {
            return 0;
        }
        return 1;

    case Assert_kind:
        if (at_module) {
            return appstrict_error_stmt(
                ctx, s, "ASR005",
                "executable module-level control flow is not permitted");
        }
        if (!appstrict_validate_expr(ctx, s->v.Assert.test)) {
            return 0;
        }
        if (s->v.Assert.msg != NULL
            && !appstrict_validate_expr(ctx, s->v.Assert.msg)) {
            return 0;
        }
        return 1;

    case Return_kind:
        if (s->v.Return.value != NULL) {
            return appstrict_validate_expr(ctx, s->v.Return.value);
        }
        return 1;

    case Expr_kind:
        return appstrict_validate_expr(ctx, s->v.Expr.value);

    case Assign_kind: {
        asdl_expr_seq *targets = s->v.Assign.targets;
        if (asdl_seq_LEN(targets) > 0
            && !appstrict_validate_assign_common(
                ctx, s, asdl_seq_GET(targets, 0), s->v.Assign.value)) {
            return 0;
        }
        return appstrict_validate_expr(ctx, s->v.Assign.value);
    }

    case AnnAssign_kind:
        if (!appstrict_validate_assign_common(ctx, s, s->v.AnnAssign.target,
                                              s->v.AnnAssign.value)) {
            return 0;
        }
        if (s->v.AnnAssign.annotation != NULL
            && appstrict_annotation_is_any(s->v.AnnAssign.annotation)) {
            return appstrict_error_stmt(
                ctx, s, "ASR090",
                "typing.Any is not permitted in application code");
        }
        if (s->v.AnnAssign.value != NULL) {
            return appstrict_validate_expr(ctx, s->v.AnnAssign.value);
        }
        return 1;

    case AugAssign_kind:
        return appstrict_validate_expr(ctx, s->v.AugAssign.value);

    case TypeAlias_kind:
        return appstrict_validate_expr(ctx, s->v.TypeAlias.value);

    case Pass_kind:
    case Break_kind:
    case Continue_kind:
        return 1;

    default:
        return 1;
    }
}

/* ------------------------------------------------------------------ */
/* Expressions                                                         */
/* ------------------------------------------------------------------ */

static int
appstrict_validate_comprehension(AppStrictContext *ctx, expr_ty e,
                                 asdl_comprehension_seq *generators)
{
    int ngen = asdl_seq_LEN(generators);
    if (ngen > ASR_MAX_COMPREHENSION_NESTING) {
        return appstrict_error_expr(
            ctx, e, "ASR066",
            "comprehensions may have at most one generator");
    }
    for (Py_ssize_t i = 0; i < ngen; i++) {
        comprehension_ty comp = asdl_seq_GET(generators, i);
        if (!appstrict_validate_expr(ctx, comp->iter)) {
            return 0;
        }
        if (ctx->function_depth > 0) {
            appstrict_count_target_locals(ctx, comp->target);
        }
        asdl_expr_seq *ifs = comp->ifs;
        for (Py_ssize_t j = 0; j < asdl_seq_LEN(ifs); j++) {
            /* comprehension filter: one branch point each (section 26) */
            if (ctx->function_depth > 0) {
                ctx->branch_points++;
            }
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(ifs, j))) {
                return 0;
            }
        }
    }
    return 1;
}

static int
appstrict_validate_call(AppStrictContext *ctx, expr_ty e)
{
    expr_ty func = e->v.Call.func;
    if (!appstrict_validate_expr(ctx, func)) {
        return 0;
    }
    asdl_expr_seq *args = e->v.Call.args;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(args); i++) {
        expr_ty a = asdl_seq_GET(args, i);
        if (a->kind == Starred_kind) {
            return appstrict_error_expr(
                ctx, a, "ASR053",
                "starred call expansion (*args) is not permitted");
        }
        if (!appstrict_validate_expr(ctx, a)) {
            return 0;
        }
    }
    asdl_keyword_seq *keywords = e->v.Call.keywords;
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(keywords); i++) {
        keyword_ty kw = asdl_seq_GET(keywords, i);
        if (kw->arg == NULL) {
            return appstrict_error_expr(
                ctx, e, "ASR053",
                "starred call expansion (**kwargs) is not permitted");
        }
        if (!appstrict_validate_expr(ctx, kw->value)) {
            return 0;
        }
    }
    return 1;
}

static int
appstrict_validate_expr(AppStrictContext *ctx, expr_ty e)
{
    ctx->module_ast_nodes++;
    if (ctx->module_ast_nodes > ASR_MAX_MODULE_AST_NODES) {
        return appstrict_error_expr(ctx, e, "ASR108", "module is too large");
    }

    switch (e->kind) {
    case Name_kind: {
        const char *id = PyUnicode_AsUTF8(e->v.Name.id);
        if (id == NULL) {
            return 0;
        }
        if (name_in(id, ASR_DYNAMIC_BUILTINS,
                    Py_ARRAY_LENGTH(ASR_DYNAMIC_BUILTINS))) {
            const char *rule = "ASR020";
            if (strcmp(id, "exec") == 0) {
                rule = "ASR021";
            }
            else if (strcmp(id, "compile") == 0) {
                rule = "ASR022";
            }
            else if (strcmp(id, "__import__") == 0) {
                rule = "ASR023";
            }
            return appstrict_error_expr(
                ctx, e, rule,
                "dynamic code generation is not permitted in application code");
        }
        if (name_in(id, ASR_REFLECT_BUILTINS,
                    Py_ARRAY_LENGTH(ASR_REFLECT_BUILTINS))) {
            return appstrict_error_expr(
                ctx, e, "ASR024",
                "reflection / namespace mutation is not permitted in "
                "application code");
        }
        return 1;
    }

    case Attribute_kind: {
        const char *attr = PyUnicode_AsUTF8(e->v.Attribute.attr);
        if (attr != NULL
            && name_in(attr, ASR_DUNDER_ATTRS,
                       Py_ARRAY_LENGTH(ASR_DUNDER_ATTRS))) {
            return appstrict_error_expr(
                ctx, e, "ASR025",
                "access to this introspection attribute is not permitted");
        }
        return appstrict_validate_expr(ctx, e->v.Attribute.value);
    }

    case Lambda_kind:
        return appstrict_error_expr(
            ctx, e, "ASR061",
            "lambda expressions are not permitted in application code");

    case NamedExpr_kind:
        return appstrict_error_expr(
            ctx, e, "ASR062",
            "assignment expressions are not permitted in application code");

    case Yield_kind:
        return appstrict_error_expr(
            ctx, e, "ASR064",
            "yield is not permitted in application code");

    case YieldFrom_kind:
        return appstrict_error_expr(
            ctx, e, "ASR065",
            "yield from is not permitted in application code");

    case Call_kind:
        return appstrict_validate_call(ctx, e);

    case BoolOp_kind: {
        asdl_expr_seq *values = e->v.BoolOp.values;
        if (ctx->function_depth > 0) {
            /* BoolOp contribution: number_of_values - 1 (section 26) */
            ctx->branch_points += (int)asdl_seq_LEN(values) - 1;
        }
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(values); i++) {
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(values, i))) {
                return 0;
            }
        }
        return 1;
    }

    case IfExp_kind:
        if (ctx->function_depth > 0) {
            ctx->branch_points++;
        }
        if (!appstrict_validate_expr(ctx, e->v.IfExp.test)
            || !appstrict_validate_expr(ctx, e->v.IfExp.body)
            || !appstrict_validate_expr(ctx, e->v.IfExp.orelse)) {
            return 0;
        }
        return 1;

    case ListComp_kind:
        if (!appstrict_validate_comprehension(ctx, e,
                                              e->v.ListComp.generators)) {
            return 0;
        }
        return appstrict_validate_expr(ctx, e->v.ListComp.elt);
    case SetComp_kind:
        if (!appstrict_validate_comprehension(ctx, e,
                                              e->v.SetComp.generators)) {
            return 0;
        }
        return appstrict_validate_expr(ctx, e->v.SetComp.elt);
    case DictComp_kind:
        if (!appstrict_validate_comprehension(ctx, e,
                                              e->v.DictComp.generators)) {
            return 0;
        }
        if (e->v.DictComp.key != NULL
            && !appstrict_validate_expr(ctx, e->v.DictComp.key)) {
            return 0;
        }
        return appstrict_validate_expr(ctx, e->v.DictComp.value);
    case GeneratorExp_kind:
        if (!appstrict_validate_comprehension(ctx, e,
                                              e->v.GeneratorExp.generators)) {
            return 0;
        }
        return appstrict_validate_expr(ctx, e->v.GeneratorExp.elt);

    case Await_kind:
        return appstrict_validate_expr(ctx, e->v.Await.value);
    case BinOp_kind:
        if (!appstrict_validate_expr(ctx, e->v.BinOp.left)) {
            return 0;
        }
        return appstrict_validate_expr(ctx, e->v.BinOp.right);
    case UnaryOp_kind:
        return appstrict_validate_expr(ctx, e->v.UnaryOp.operand);
    case Compare_kind: {
        if (!appstrict_validate_expr(ctx, e->v.Compare.left)) {
            return 0;
        }
        asdl_expr_seq *comp = e->v.Compare.comparators;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(comp); i++) {
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(comp, i))) {
                return 0;
            }
        }
        return 1;
    }
    case Subscript_kind:
        if (!appstrict_validate_expr(ctx, e->v.Subscript.value)) {
            return 0;
        }
        return appstrict_validate_expr(ctx, e->v.Subscript.slice);
    case Starred_kind:
        return appstrict_validate_expr(ctx, e->v.Starred.value);
    case List_kind:
    case Tuple_kind: {
        asdl_expr_seq *elts = e->kind == List_kind
                              ? e->v.List.elts : e->v.Tuple.elts;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(elts); i++) {
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(elts, i))) {
                return 0;
            }
        }
        return 1;
    }
    case Dict_kind: {
        asdl_expr_seq *keys = e->v.Dict.keys;
        asdl_expr_seq *values = e->v.Dict.values;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(keys); i++) {
            expr_ty k = asdl_seq_GET(keys, i);
            if (k != NULL && !appstrict_validate_expr(ctx, k)) {
                return 0;
            }
        }
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(values); i++) {
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(values, i))) {
                return 0;
            }
        }
        return 1;
    }
    case Set_kind: {
        asdl_expr_seq *elts = e->v.Set.elts;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(elts); i++) {
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(elts, i))) {
                return 0;
            }
        }
        return 1;
    }
    case Slice_kind:
        if (e->v.Slice.lower != NULL
            && !appstrict_validate_expr(ctx, e->v.Slice.lower)) {
            return 0;
        }
        if (e->v.Slice.upper != NULL
            && !appstrict_validate_expr(ctx, e->v.Slice.upper)) {
            return 0;
        }
        if (e->v.Slice.step != NULL
            && !appstrict_validate_expr(ctx, e->v.Slice.step)) {
            return 0;
        }
        return 1;
    case JoinedStr_kind:
    case TemplateStr_kind: {
        asdl_expr_seq *values = e->kind == JoinedStr_kind
                                ? e->v.JoinedStr.values
                                : e->v.TemplateStr.values;
        for (Py_ssize_t i = 0; i < asdl_seq_LEN(values); i++) {
            if (!appstrict_validate_expr(ctx, asdl_seq_GET(values, i))) {
                return 0;
            }
        }
        return 1;
    }
    case FormattedValue_kind:
    case Interpolation_kind: {
        expr_ty value = e->kind == FormattedValue_kind
                        ? e->v.FormattedValue.value
                        : e->v.Interpolation.value;
        expr_ty fspec = e->kind == FormattedValue_kind
                        ? e->v.FormattedValue.format_spec
                        : e->v.Interpolation.format_spec;
        if (!appstrict_validate_expr(ctx, value)) {
            return 0;
        }
        if (fspec != NULL) {
            return appstrict_validate_expr(ctx, fspec);
        }
        return 1;
    }
    case Constant_kind:
        return 1;

    default:
        return 1;
    }
}

/* ------------------------------------------------------------------ */
/* Module entry point                                                  */
/* ------------------------------------------------------------------ */

int
_PyAppStrict_Validate(mod_ty mod, PyObject *filename)
{
    if (mod == NULL || mod->kind != Module_kind) {
        return 1;                       /* Interactive/Expression: skip */
    }

    AppStrictContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.filename = filename;

    asdl_stmt_seq *body = mod->v.Module.body;

    /* First pass: module-structure whitelist (ASR005) before descending
       into bodies, so the most useful diagnostic wins. */
    for (Py_ssize_t i = 0; i < asdl_seq_LEN(body); i++) {
        stmt_ty s = asdl_seq_GET(body, i);
        if (!appstrict_module_stmt_allowed(s)) {
            return appstrict_error_stmt(
                &ctx, s, "ASR005",
                "executable module-level control flow is not permitted");
        }
    }

    for (Py_ssize_t i = 0; i < asdl_seq_LEN(body); i++) {
        if (!appstrict_validate_stmt(&ctx, asdl_seq_GET(body, i))) {
            return 0;
        }
    }
    return 1;
}
