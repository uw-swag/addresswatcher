/* { dg-do assemble } */
/* { dg-require-effective-target arm_v8_2a_bf16_neon_ok } */
/* { dg-add-options arm_v8_2a_bf16_neon } */
/* { dg-additional-options "-O3 --save-temps" } */

#include "arm_neon.h"

void
test_vst1_lane_bf16 (bfloat16_t *a, bfloat16x4_t b)
{
  vst1_lane_bf16 (a, b, 1);
}

void
test_vst1q_lane_bf16 (bfloat16_t *a, bfloat16x8_t b)
{
  vst1q_lane_bf16 (a, b, 2);
}

/* { dg-final { scan-assembler "vst1.16\t{d0\\\[1\\\]}, \\\[r0\\\]" } } */
/* { dg-final { scan-assembler "vst1.16\t{d0\\\[2\\\]}, \\\[r0\\\]" } } */
