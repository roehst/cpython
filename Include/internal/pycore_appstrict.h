/* AppStrict: statically restricted application Python.

   AppStrict restricts only application-owned Python source files, selected
   by path using the --app-strict-root / --app-strict-exclude command line
   options.  Standard-library code, site-packages, C extensions and other
   dependencies keep compiling and running as ordinary unrestricted Python.

   This is a static structural restriction, not a security boundary.  See
   InternalDocs/appstrict.md for the full design document.
*/

#ifndef Py_INTERNAL_APPSTRICT_H
#define Py_INTERNAL_APPSTRICT_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

#include "pycore_ast.h"           // mod_ty

/* Return 1 if the given filename belongs to an AppStrict-restricted root
   (and is not excluded), 0 otherwise.  Returns -1 with an exception set on
   internal error. */
extern int _PyAppStrict_IsRestrictedFilename(
    PyThreadState *tstate,
    PyObject *filename);

/* Validate the module AST against the AppStrict rules.

   Returns 1 on success, 0 when the module is rejected (a SyntaxError with a
   stable [ASRxxx] identifier is set), and -1 on internal error. */
extern int _PyAppStrict_Validate(
    mod_ty mod,
    PyObject *filename);

#ifdef __cplusplus
}
#endif
#endif /* !Py_INTERNAL_APPSTRICT_H */
