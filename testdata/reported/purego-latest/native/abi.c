#include <stdint.h>

uintptr_t probe_ints15(
    uintptr_t a1,
    uintptr_t a2,
    uintptr_t a3,
    uintptr_t a4,
    uintptr_t a5,
    uintptr_t a6,
    uintptr_t a7,
    uintptr_t a8,
    uintptr_t a9,
    uintptr_t a10,
    uintptr_t a11,
    uintptr_t a12,
    uintptr_t a13,
    uintptr_t a14,
    uintptr_t a15) {
    const uintptr_t values[] = {
        a1, a2, a3, a4, a5, a6, a7, a8,
        a9, a10, a11, a12, a13, a14, a15
    };
    uintptr_t result = 0;
    for (unsigned i = 0; i < 15; i++) {
        result += values[i] * (i + 1);
    }
    return result;
}

double probe_floats15(
    double a1,
    double a2,
    double a3,
    double a4,
    double a5,
    double a6,
    double a7,
    double a8,
    double a9,
    double a10,
    double a11,
    double a12,
    double a13,
    double a14,
    double a15) {
    const double values[] = {
        a1, a2, a3, a4, a5, a6, a7, a8,
        a9, a10, a11, a12, a13, a14, a15
    };
    double result = 0;
    for (unsigned i = 0; i < 15; i++) {
        result += values[i] * (i + 1);
    }
    return result;
}

double probe_mixed15(
    uintptr_t i1, double f1, uintptr_t i2, double f2,
    uintptr_t i3, double f3, uintptr_t i4, double f4,
    uintptr_t i5, double f5, uintptr_t i6, double f6,
    uintptr_t i7, double f7, uintptr_t i8) {
    const uintptr_t integers[] = {i1, i2, i3, i4, i5, i6, i7, i8};
    const double floats[] = {f1, f2, f3, f4, f5, f6, f7};
    double result = 0;
    for (unsigned i = 0; i < 8; i++) {
        result += integers[i] * (i + 1);
    }
    for (unsigned i = 0; i < 7; i++) {
        result += floats[i] * (i + 17);
    }
    return result;
}
