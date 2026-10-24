/*
 * tests/test_p5_app.c — Synthetic PT_INTERP app (ET_EXEC + PT_INTERP).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Freestanding V8-only app whose PT_INTERP names /tmp/sparc32rt-p5interp
 * (the companion ET_DYN probe in tests/test_p5_interp.c). The loader (and
 * qemu) run the interpreter first; it validates the auxv and jumps here.
 * Expected stdout with the companion probe: exactly
 * "interp-first\napp-ran\n", exit 0, on qemu-sparc -cpu LEON3, --interp
 * and --dbt alike.
 *
 * Build (inside the sparc32rt-oracle container):
 *   sparc64-linux-gnu-gcc -m32 -nostdlib -shared -Wl,-e,_start \
 *     -o /tmp/sparc32rt-p5interp tests/test_p5_interp.c
 *   sparc64-linux-gnu-gcc -m32 -fno-pie -no-pie -nostdlib \
 *     -Wl,--export-dynamic -Wl,--dynamic-linker,/tmp/sparc32rt-p5interp \
 *     -o /tmp/sparc32rt-p5app tests/test_p5_app.c
 * (--export-dynamic forces a dynamic link so ld emits PT_INTERP despite
 * the driver's own default -dynamic-linker; EM_SPARC, e_flags stay 0.)
 * Verify: readelf -l shows PT_INTERP with that path.
 *
 * Pure top-level asm, V8 encodings only.
 */
__asm__(
"\t.text\n\t.align 4\n\t.global _start\n"
"_start:\n"
"\tsethi %hi(m_ran), %g2\nor %g2, %lo(m_ran), %g2\n\tcall puts\n\tnop\n"
"\tmov 0, %o0\n\tmov 1, %g1\n\tta 0x10\n"
"puts:\n\tmov %g2, %g4\n"
"1:\n\tldub [%g4], %g3\n\ttst %g3\n\tbz 2f\n\tnop\n\tadd %g4, 1, %g4\n\tba 1b\n\tnop\n"
"2:\n\tsub %g4, %g2, %o2\n\tmov %g2, %o1\n\tmov 1, %o0\n\tmov 4, %g1\n\tta 0x10\n\tretl\n\tnop\n"
"\t.section .interp,\"a\",@progbits\n\t.align 4\n"
"interp_path:\n\t.asciz \"/tmp/sparc32rt-p5interp\"\n"
"\t.data\n\t.align 4\n"
"m_ran:\n\t.asciz \"app-ran\\n\"\n"
);
