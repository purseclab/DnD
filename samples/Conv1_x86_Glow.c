/* This file was generated by the Hex-Rays decompiler version 7.7.0.220218.
   Copyright (c) 2007-2021 Hex-Rays <info@hex-rays.com>

   Detected compiler: GNU C++
*/

//----- (0000000000004170) ----------------------------------------------------
unsigned __int64 __fastcall sub_4170(__int64 a1, __int64 a2, __int64 a3, _OWORD *a4)
{
  _OWORD *v4; // r8
  __int64 v5; // r9
  __int64 v6; // rax
  __int64 v7; // r10
  __int64 v8; // r11
  _OWORD *v9; // rsi
  __int64 v10; // rdi
  _OWORD *v11; // rdi
  __int64 v12; // rsi
  _OWORD *v13; // rsi
  __int64 v14; // rdi
  _OWORD *v15; // rdi
  __int64 v16; // rsi
  _OWORD *v17; // rsi
  __int64 v18; // rdi
  _OWORD *v19; // rdi
  __int64 v20; // rsi
  _OWORD *v21; // rsi
  __int64 v22; // rdi
  __int64 v23; // rsi
  unsigned __int64 result; // rax
  __int64 v25; // r14
  __int64 v26; // rdi
  unsigned __int64 v27; // r13
  __int64 v28; // rbx
  __int64 v29; // rcx
  __int64 v30; // rbp
  __int64 v31; // r8
  __int64 v32; // rsi
  __int64 v33; // r9
  __int64 v34; // r10
  __int64 v35; // r11
  float *v36; // r15
  __int64 v37; // rax
  __int64 v38; // r12
  __int64 v39; // rax
  float v40; // xmm1_4
  float v41; // xmm3_4
  float *v42; // rdi
  __m128 v43; // xmm2
  __m128 v44; // xmm11
  __m128 v45; // xmm10
  __m128 v46; // xmm1
  __m128 v47; // xmm0
  __m128 v48; // xmm6
  __m128 v49; // xmm5
  __m128 v50; // xmm13
  __m128 v51; // xmm12
  __m128 v52; // xmm8
  __m128 v53; // xmm7
  __m128 v54; // xmm3
  __m128 v55; // xmm15
  __m128 v56; // xmm4
  __m128 v57; // xmm9
  __m128 v58; // xmm14
  float v59; // xmm12_4
  __m128 v60; // xmm3
  __m128 v61; // xmm4
  __m128 v62; // xmm7
  __m128 v63; // xmm11
  __m128 v64; // xmm2
  __m128 v65; // xmm3
  __m128 v66; // xmm4
  __m128 v67; // xmm7
  __m128 v68; // xmm10
  __m128 v69; // xmm2
  float v70; // xmm11_4
  __m128 v71; // xmm3
  __m128 v72; // xmm1
  __m128 v73; // xmm4
  __m128 v74; // xmm7
  __m128 v75; // xmm2
  __m128 v76; // xmm0
  __m128 v77; // xmm1
  __m128 v78; // xmm3
  __m128 v79; // xmm2
  __m128 v80; // xmm0
  __m128 v81; // xmm4
  __m128 v82; // xmm7
  __m128 v83; // xmm5
  __m128 v84; // xmm1
  __m128 v85; // xmm6
  float v86; // xmm8_4
  __m128 v87; // xmm3
  __m128 v88; // xmm13
  __m128 v89; // xmm0
  __m128 v90; // xmm4
  __m128 v91; // xmm7
  float v92; // xmm1_4
  float v93; // xmm9_4
  float v94; // xmm12_4
  __m128 v95; // xmm3
  __m128 v96; // xmm6
  __m128 v97; // xmm5
  float v98; // xmm4_4
  float v99; // xmm14_4
  float v100; // xmm9_4
  __m128 v101; // xmm2
  __m128 v102; // xmm0
  float v103; // xmm1_4
  float v104; // xmm7_4
  float v105; // xmm14_4
  __m128 v106; // xmm3
  float v107; // xmm2_4
  float v108; // xmm5_4
  float v109; // xmm7_4
  float v110; // xmm1_4
  float v111; // xmm0_4
  float v112; // xmm5_4
  float v113; // xmm3_4
  float v114; // xmm0_4
  bool v115; // [rsp+1h] [rbp-A1h]
  __int64 v118; // [rsp+Ah] [rbp-98h]
  float *v119; // [rsp+12h] [rbp-90h]
  unsigned __int64 v120; // [rsp+1Ah] [rbp-88h]
  __int64 v121; // [rsp+22h] [rbp-80h]
  __int64 v122; // [rsp+2Ah] [rbp-78h]
  __int64 v123; // [rsp+32h] [rbp-70h]
  __int64 v124; // [rsp+3Ah] [rbp-68h]
  __int64 v125; // [rsp+42h] [rbp-60h]
  unsigned __int64 v126; // [rsp+4Ah] [rbp-58h]
  __int64 v127; // [rsp+52h] [rbp-50h]
  float *v128; // [rsp+5Ah] [rbp-48h]
  __int64 v129; // [rsp+62h] [rbp-40h]
  __int64 v130; // [rsp+6Ah] [rbp-38h]

  v4 = a4 + 16;
  v5 = 0LL;
  v6 = a1;
  do
  {
    v8 = v5 << 11;
    v9 = (_OWORD *)(a1 + (v5 << 11) + 256);
    if ( (v5 << 11) + a1 >= (unsigned __int64)v4 || v9 <= a4 )
    {
      *(_OWORD *)(a1 + (v5 << 11)) = *a4;
      *(_OWORD *)(a1 + ((v5 << 11) | 0x10)) = a4[1];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x20)) = a4[2];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x30)) = a4[3];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x40)) = a4[4];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x50)) = a4[5];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x60)) = a4[6];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x70)) = a4[7];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x80)) = a4[8];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x90)) = a4[9];
      *(_OWORD *)(a1 + ((v5 << 11) | 0xA0)) = a4[10];
      *(_OWORD *)(a1 + ((v5 << 11) | 0xB0)) = a4[11];
      *(_OWORD *)(a1 + ((v5 << 11) | 0xC0)) = a4[12];
      *(_OWORD *)(a1 + ((v5 << 11) | 0xD0)) = a4[13];
      *(_OWORD *)(a1 + ((v5 << 11) | 0xE0)) = a4[14];
      *(_OWORD *)(a1 + ((v5 << 11) | 0xF0)) = a4[15];
    }
    else
    {
      v10 = -64LL;
      do
      {
        *(_DWORD *)(v6 + 4 * v10 + 256) = *((_DWORD *)a4 + v10 + 64);
        ++v10;
      }
      while ( v10 );
    }
    v11 = (_OWORD *)(a1 + v8 + 512);
    if ( v9 >= v4 || v11 <= a4 )
    {
      *v9 = *a4;
      *(_OWORD *)(a1 + ((v5 << 11) | 0x110)) = a4[1];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x120)) = a4[2];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x130)) = a4[3];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x140)) = a4[4];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x150)) = a4[5];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x160)) = a4[6];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x170)) = a4[7];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x180)) = a4[8];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x190)) = a4[9];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x1A0)) = a4[10];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x1B0)) = a4[11];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x1C0)) = a4[12];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x1D0)) = a4[13];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x1E0)) = a4[14];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x1F0)) = a4[15];
    }
    else
    {
      v12 = -64LL;
      do
      {
        *(_DWORD *)(v6 + 4 * v12 + 512) = *((_DWORD *)a4 + v12 + 64);
        ++v12;
      }
      while ( v12 );
    }
    v13 = (_OWORD *)(a1 + v8 + 768);
    if ( v11 >= v4 || v13 <= a4 )
    {
      *v11 = *a4;
      *(_OWORD *)(a1 + ((v5 << 11) | 0x210)) = a4[1];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x220)) = a4[2];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x230)) = a4[3];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x240)) = a4[4];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x250)) = a4[5];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x260)) = a4[6];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x270)) = a4[7];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x280)) = a4[8];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x290)) = a4[9];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x2A0)) = a4[10];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x2B0)) = a4[11];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x2C0)) = a4[12];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x2D0)) = a4[13];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x2E0)) = a4[14];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x2F0)) = a4[15];
    }
    else
    {
      v14 = -64LL;
      do
      {
        *(_DWORD *)(v6 + 4 * v14 + 768) = *((_DWORD *)a4 + v14 + 64);
        ++v14;
      }
      while ( v14 );
    }
    v15 = (_OWORD *)(a1 + v8 + 1024);
    if ( v13 >= v4 || v15 <= a4 )
    {
      *v13 = *a4;
      *(_OWORD *)(a1 + ((v5 << 11) | 0x310)) = a4[1];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x320)) = a4[2];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x330)) = a4[3];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x340)) = a4[4];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x350)) = a4[5];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x360)) = a4[6];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x370)) = a4[7];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x380)) = a4[8];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x390)) = a4[9];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x3A0)) = a4[10];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x3B0)) = a4[11];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x3C0)) = a4[12];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x3D0)) = a4[13];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x3E0)) = a4[14];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x3F0)) = a4[15];
    }
    else
    {
      v16 = -64LL;
      do
      {
        *(_DWORD *)(v6 + 4 * v16 + 1024) = *((_DWORD *)a4 + v16 + 64);
        ++v16;
      }
      while ( v16 );
    }
    v17 = (_OWORD *)(a1 + v8 + 1280);
    if ( v15 >= v4 || v17 <= a4 )
    {
      *v15 = *a4;
      *(_OWORD *)(a1 + ((v5 << 11) | 0x410)) = a4[1];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x420)) = a4[2];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x430)) = a4[3];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x440)) = a4[4];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x450)) = a4[5];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x460)) = a4[6];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x470)) = a4[7];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x480)) = a4[8];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x490)) = a4[9];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x4A0)) = a4[10];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x4B0)) = a4[11];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x4C0)) = a4[12];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x4D0)) = a4[13];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x4E0)) = a4[14];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x4F0)) = a4[15];
    }
    else
    {
      v18 = -64LL;
      do
      {
        *(_DWORD *)(v6 + 4 * v18 + 1280) = *((_DWORD *)a4 + v18 + 64);
        ++v18;
      }
      while ( v18 );
    }
    v19 = (_OWORD *)(a1 + v8 + 1536);
    if ( v17 >= v4 || v19 <= a4 )
    {
      *v17 = *a4;
      *(_OWORD *)(a1 + ((v5 << 11) | 0x510)) = a4[1];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x520)) = a4[2];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x530)) = a4[3];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x540)) = a4[4];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x550)) = a4[5];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x560)) = a4[6];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x570)) = a4[7];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x580)) = a4[8];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x590)) = a4[9];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x5A0)) = a4[10];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x5B0)) = a4[11];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x5C0)) = a4[12];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x5D0)) = a4[13];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x5E0)) = a4[14];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x5F0)) = a4[15];
    }
    else
    {
      v20 = -64LL;
      do
      {
        *(_DWORD *)(v6 + 4 * v20 + 1536) = *((_DWORD *)a4 + v20 + 64);
        ++v20;
      }
      while ( v20 );
    }
    v21 = (_OWORD *)(a1 + v8 + 1792);
    if ( v19 >= v4 || v21 <= a4 )
    {
      *v19 = *a4;
      *(_OWORD *)(a1 + ((v5 << 11) | 0x610)) = a4[1];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x620)) = a4[2];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x630)) = a4[3];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x640)) = a4[4];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x650)) = a4[5];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x660)) = a4[6];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x670)) = a4[7];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x680)) = a4[8];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x690)) = a4[9];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x6A0)) = a4[10];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x6B0)) = a4[11];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x6C0)) = a4[12];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x6D0)) = a4[13];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x6E0)) = a4[14];
      *(_OWORD *)(a1 + ((v5 << 11) | 0x6F0)) = a4[15];
      if ( v21 >= v4 )
        goto LABEL_2;
    }
    else
    {
      v22 = -64LL;
      do
      {
        *(_DWORD *)(v6 + 4 * v22 + 1792) = *((_DWORD *)a4 + v22 + 64);
        ++v22;
      }
      while ( v22 );
      if ( v21 >= v4 )
      {
LABEL_2:
        *v21 = *a4;
        v7 = v5 << 11;
        *(_OWORD *)(a1 + (v7 | 0x710)) = a4[1];
        *(_OWORD *)(a1 + (v7 | 0x720)) = a4[2];
        *(_OWORD *)(a1 + (v7 | 0x730)) = a4[3];
        *(_OWORD *)(a1 + (v7 | 0x740)) = a4[4];
        *(_OWORD *)(a1 + (v7 | 0x750)) = a4[5];
        *(_OWORD *)(a1 + (v7 | 0x760)) = a4[6];
        *(_OWORD *)(a1 + (v7 | 0x770)) = a4[7];
        *(_OWORD *)(a1 + (v7 | 0x780)) = a4[8];
        *(_OWORD *)(a1 + (v7 | 0x790)) = a4[9];
        *(_OWORD *)(a1 + (v7 | 0x7A0)) = a4[10];
        *(_OWORD *)(a1 + (v7 | 0x7B0)) = a4[11];
        *(_OWORD *)(a1 + (v7 | 0x7C0)) = a4[12];
        *(_OWORD *)(a1 + (v7 | 0x7D0)) = a4[13];
        *(_OWORD *)(a1 + (v7 | 0x7E0)) = a4[14];
        *(_OWORD *)(a1 + ((v5 << 11) | 0x7F0)) = a4[15];
        goto LABEL_3;
      }
    }
    if ( a1 + v8 + 2048 <= (unsigned __int64)a4 )
      goto LABEL_2;
    v23 = -64LL;
    do
    {
      *(_DWORD *)(v6 + 4 * v23 + 2048) = *((_DWORD *)a4 + v23 + 64);
      ++v23;
    }
    while ( v23 );
LABEL_3:
    ++v5;
    v6 += 2048LL;
  }
  while ( v5 != 8 );
  v119 = (float *)(a1 + 28);
  v118 = a2 + 112;
  result = 0LL;
  do
  {
    v120 = result;
    v121 = 3 * result;
    v25 = v118;
    v26 = 0LL;
    do
    {
      v123 = 3 * (v26 + v121);
      v122 = v25;
      v27 = 0LL;
      v125 = v26;
      do
      {
        v115 = (v26 ^ 2 | v27 ^ 2) == 0;
        v28 = 32 * (v27 + v123);
        v29 = v28 + 4;
        v30 = v28 + 8;
        v31 = v28 + 12;
        v32 = v28 + 16;
        v33 = v28 + 20;
        v34 = v28 + 24;
        v35 = v28 + 28;
        v124 = v25;
        v36 = v119;
        v37 = 0LL;
        v126 = v27;
        do
        {
          v130 = v26 + 2 * v37;
          v127 = v37;
          v129 = 8 * v37;
          v38 = -2048LL;
          v128 = v36;
          v39 = 0LL;
          do
          {
            if ( (v130 | v27) < 0x10 )
            {
              v43 = *(__m128 *)(v25 + v38 + 1936);
              v44 = *(__m128 *)(v25 + v38 + 1952);
              v45 = *(__m128 *)(v25 + v38 + 1968);
              v46 = *(__m128 *)(v25 + v38 + 1984);
              v47 = *(__m128 *)(v25 + v38 + 2000);
              v48 = *(__m128 *)(v25 + v38 + 2016);
              v49 = *(__m128 *)(v25 + v38 + 2032);
              v50 = *(__m128 *)(v25 + v38 + 2048);
              v51 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v35), v50),
                      _mm_add_ps(
                        _mm_mul_ps(*(__m128 *)(a3 + 4 * v34), v49),
                        _mm_add_ps(
                          _mm_mul_ps(*(__m128 *)(a3 + 4 * v33), v48),
                          _mm_add_ps(
                            _mm_mul_ps(*(__m128 *)(a3 + 4 * v32), v47),
                            _mm_add_ps(
                              _mm_mul_ps(*(__m128 *)(a3 + 4 * v31), v46),
                              _mm_add_ps(
                                _mm_mul_ps(*(__m128 *)(a3 + 4 * v30), v45),
                                _mm_add_ps(
                                  _mm_mul_ps(*(__m128 *)(a3 + 4 * v29), v44),
                                  _mm_mul_ps(*(__m128 *)(a3 + 4 * v28), v43))))))));
              v52 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v35 + 1152), v50),
                      _mm_add_ps(
                        _mm_mul_ps(*(__m128 *)(a3 + 4 * v34 + 1152), v49),
                        _mm_add_ps(
                          _mm_mul_ps(*(__m128 *)(a3 + 4 * v33 + 1152), v48),
                          _mm_add_ps(
                            _mm_mul_ps(*(__m128 *)(a3 + 4 * v32 + 1152), v47),
                            _mm_add_ps(
                              _mm_mul_ps(*(__m128 *)(a3 + 4 * v31 + 1152), v46),
                              _mm_add_ps(
                                _mm_mul_ps(*(__m128 *)(a3 + 4 * v30 + 1152), v45),
                                _mm_add_ps(
                                  _mm_mul_ps(*(__m128 *)(a3 + 4 * v29 + 1152), v44),
                                  _mm_mul_ps(*(__m128 *)(a3 + 4 * v28 + 1152), v43))))))));
              v53 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v35 + 2304), v50),
                      _mm_add_ps(
                        _mm_mul_ps(*(__m128 *)(a3 + 4 * v34 + 2304), v49),
                        _mm_add_ps(
                          _mm_mul_ps(*(__m128 *)(a3 + 4 * v33 + 2304), v48),
                          _mm_add_ps(
                            _mm_mul_ps(*(__m128 *)(a3 + 4 * v32 + 2304), v47),
                            _mm_add_ps(
                              _mm_mul_ps(*(__m128 *)(a3 + 4 * v31 + 2304), v46),
                              _mm_add_ps(
                                _mm_mul_ps(*(__m128 *)(a3 + 4 * v30 + 2304), v45),
                                _mm_add_ps(
                                  _mm_mul_ps(*(__m128 *)(a3 + 4 * v29 + 2304), v44),
                                  _mm_mul_ps(*(__m128 *)(a3 + 4 * v28 + 2304), v43))))))));
              v54 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v35 + 3456), v50),
                      _mm_add_ps(
                        _mm_mul_ps(*(__m128 *)(a3 + 4 * v34 + 3456), v49),
                        _mm_add_ps(
                          _mm_mul_ps(*(__m128 *)(a3 + 4 * v33 + 3456), v48),
                          _mm_add_ps(
                            _mm_mul_ps(*(__m128 *)(a3 + 4 * v32 + 3456), v47),
                            _mm_add_ps(
                              _mm_mul_ps(*(__m128 *)(a3 + 4 * v31 + 3456), v46),
                              _mm_add_ps(
                                _mm_mul_ps(*(__m128 *)(a3 + 4 * v30 + 3456), v45),
                                _mm_add_ps(
                                  _mm_mul_ps(*(__m128 *)(a3 + 4 * v29 + 3456), v44),
                                  _mm_mul_ps(*(__m128 *)(a3 + 4 * v28 + 3456), v43))))))));
              v55 = _mm_add_ps((__m128)_mm_unpackhi_pd((__m128d)v51, (__m128d)v51), v51);
              v56 = _mm_add_ps((__m128)_mm_unpackhi_pd((__m128d)v52, (__m128d)v52), v52);
              v57 = _mm_add_ps((__m128)_mm_unpackhi_pd((__m128d)v53, (__m128d)v53), v53);
              v58 = _mm_add_ps((__m128)_mm_unpackhi_pd((__m128d)v54, (__m128d)v54), v54);
              v59 = _mm_shuffle_ps(v56, v56, 229).m128_f32[0] + v56.m128_f32[0];
              v60 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v29 + 5760), v44),
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v28 + 5760), v43));
              v61 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v29 + 6912), v44),
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v28 + 6912), v43));
              v62 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v29 + 8064), v44),
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v28 + 8064), v43));
              v63 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v30 + 4608), v45),
                      _mm_add_ps(
                        _mm_mul_ps(*(__m128 *)(a3 + 4 * v29 + 4608), v44),
                        _mm_mul_ps(*(__m128 *)(a3 + 4 * v28 + 4608), v43)));
              v64 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v30 + 5760), v45), v60);
              v65 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v30 + 6912), v45), v61);
              v66 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v30 + 8064), v45), v62);
              v67 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v31 + 4608), v46), v63);
              v68 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v31 + 5760), v46), v64);
              v69 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v31 + 6912), v46), v65);
              LODWORD(v70) = _mm_shuffle_ps(v57, v57, 229).m128_u32[0];
              v71 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v31 + 8064), v46), v66);
              v72 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v32 + 4608), v47), v67);
              v73 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v32 + 5760), v47), v68);
              v74 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v32 + 6912), v47), v69);
              v75 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v32 + 8064), v47), v71);
              v76 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v33 + 4608), v48), v72);
              v77 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v33 + 5760), v48), v73);
              v78 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v33 + 8064), v48), v75);
              v79 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v34 + 4608), v49), v76);
              v80 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v34 + 6912), v49),
                      _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v33 + 6912), v48), v74));
              v81 = _mm_mul_ps(*(__m128 *)(a3 + 4 * v34 + 8064), v49);
              v82 = _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v35 + 4608), v50), v79);
              v83 = _mm_add_ps(
                      _mm_mul_ps(*(__m128 *)(a3 + 4 * v35 + 5760), v50),
                      _mm_add_ps(_mm_mul_ps(*(__m128 *)(a3 + 4 * v34 + 5760), v49), v77));
              v84 = _mm_mul_ps(*(__m128 *)(a3 + 4 * v35 + 6912), v50);
              v85 = (__m128)_mm_unpackhi_pd((__m128d)v82, (__m128d)v82);
              v86 = (float)(_mm_shuffle_ps(v55, v55, 229).m128_f32[0] + v55.m128_f32[0]) + *(v36 - 7);
              v42 = (float *)(a1 + ((4 * (v120 + ((v39 + v129) << 6))) | 0x1C));
              if ( v115 )
                v86 = fmaxf(v86, 0.0);
              v87 = _mm_add_ps(v78, v81);
              v88 = _mm_mul_ps(v50, *(__m128 *)(a3 + 4 * v35 + 8064));
              v89 = _mm_add_ps(v80, v84);
              v90 = (__m128)_mm_unpackhi_pd((__m128d)v83, (__m128d)v83);
              v91 = _mm_add_ps(v82, v85);
              LODWORD(v92) = _mm_shuffle_ps(v58, v58, 229).m128_u32[0];
              v93 = v57.m128_f32[0] + v70;
              *(v36 - 7) = v86;
              v94 = v59 + *(v36 - 6);
              if ( v115 )
                v94 = fmaxf(v94, 0.0);
              v95 = _mm_add_ps(v87, v88);
              v96 = (__m128)_mm_unpackhi_pd((__m128d)v89, (__m128d)v89);
              v97 = _mm_add_ps(v83, v90);
              LODWORD(v98) = _mm_shuffle_ps(v91, v91, 229).m128_u32[0];
              v99 = v58.m128_f32[0] + v92;
              *(v36 - 6) = v94;
              v100 = v93 + *(v36 - 5);
              if ( v115 )
                v100 = fmaxf(v100, 0.0);
              v101 = (__m128)_mm_unpackhi_pd((__m128d)v95, (__m128d)v95);
              v102 = _mm_add_ps(v89, v96);
              LODWORD(v103) = _mm_shuffle_ps(v97, v97, 229).m128_u32[0];
              v104 = v91.m128_f32[0] + v98;
              *(v36 - 5) = v100;
              v105 = v99 + *(v36 - 4);
              if ( v115 )
                v105 = fmaxf(v105, 0.0);
              v106 = _mm_add_ps(v95, v101);
              LODWORD(v107) = _mm_shuffle_ps(v102, v102, 229).m128_u32[0];
              v108 = v97.m128_f32[0] + v103;
              *(v36 - 4) = v105;
              v109 = v104 + *(v36 - 3);
              if ( v115 )
                v109 = fmaxf(v109, 0.0);
              LODWORD(v110) = _mm_shuffle_ps(v106, v106, 229).m128_u32[0];
              v111 = v102.m128_f32[0] + v107;
              *(v36 - 3) = v109;
              v112 = v108 + *(v36 - 2);
              if ( v115 )
                v112 = fmaxf(v112, 0.0);
              v113 = v106.m128_f32[0] + v110;
              *(v36 - 2) = v112;
              v114 = v111 + *(v36 - 1);
              if ( v115 )
                v114 = fmaxf(v114, 0.0);
              *(v36 - 1) = v114;
              v41 = v113 + *v36;
              if ( v115 )
                v41 = fmaxf(v41, 0.0);
              goto LABEL_60;
            }
            if ( v115 )
            {
              v40 = *(v36 - 6);
              *(v36 - 7) = fmaxf(*(v36 - 7), 0.0);
              *(v36 - 6) = fmaxf(v40, 0.0);
              *(v36 - 5) = fmaxf(*(v36 - 5), 0.0);
              *(v36 - 4) = fmaxf(*(v36 - 4), 0.0);
              *(v36 - 3) = fmaxf(*(v36 - 3), 0.0);
              *(v36 - 2) = fmaxf(*(v36 - 2), 0.0);
              *(v36 - 1) = fmaxf(*(v36 - 1), 0.0);
              v41 = fmaxf(*v36, 0.0);
              v42 = v36;
LABEL_60:
              *v42 = v41;
            }
            ++v39;
            v36 += 64;
            v27 += 2LL;
            v38 += 256LL;
          }
          while ( v38 );
          v37 = v127 + 1;
          v36 = v128 + 512;
          v25 += 4096LL;
          v26 = v125;
          v27 = v126;
        }
        while ( v127 != 7 );
        v27 = v126 + 1;
        v25 = v124 + 128;
      }
      while ( v126 != 2 );
      v26 = v125 + 1;
      v25 = v122 + 2048;
    }
    while ( v125 != 2 );
    v119 += 8;
    result = v120 + 8;
  }
  while ( v120 < 0x38 );
  return result;
}

