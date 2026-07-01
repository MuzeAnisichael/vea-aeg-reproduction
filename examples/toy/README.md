# Toy Sample

This sample is for local smoke tests only.

Build:

```bash
gcc -fno-stack-protector -no-pie -o vuln64 overflow.c
```

Optional 32-bit build:

```bash
gcc -m32 -fno-stack-protector -no-pie -o vuln32 overflow.c
```

Analyze from the repository root:

```bash
python3 -m vea_aeg analyze examples/toy/vuln64 --json
```

