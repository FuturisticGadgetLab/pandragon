#ifndef MINUNIT_H
#define MINUNIT_H

#include <stdio.h>

#define mu_assert(test, msg)  do { if (!(test)) return (msg); } while(0)
#define mu_run_test(test)     do { const char* _msg = test(); tests_run++; if (_msg) { printf("FAIL: %s\n", _msg); return 1; } } while(0)

extern int tests_run;

#endif
