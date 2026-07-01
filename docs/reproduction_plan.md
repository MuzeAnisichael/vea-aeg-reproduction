# Reproduction Plan

## 1. Environment

Use Ubuntu 18.04 or a close VM image. Install Python 3.8+, compiler/debug tools,
radare2, and the Python dependencies in `requirements.txt`.

Minimum Python dependency command:

```bash
python3 -m pip install -U pip setuptools wheel
python3 -m pip install -r requirements.txt
```

System packages:

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc-multilib g++-multilib gdb \
  binutils file patchelf libc6-i386 libc6-dbg radare2
```

## 2. Dataset

Collect local copies of the CTF binaries from the paper table:

- CTF_Wiki_ret2syscall
- CTF_Wiki_ret2shellcode
- csictf2020_pwn0x1, pwn0x2, pwn0x3
- umdctf2021_jne, umdctf2021_jnw
- csawctf2021_password
- h@cktivityctf2021_retcheck
- csawctf2020_roppity
- dctf2021_babybof, hotelrop, sanity
- dicectf2021_babyrop
- downunderctf2020_return
- downunderctf2021_deadcode, out
- lexingtonctf2021_gets, madlibs
- nahamconctf2021_smol
- redpwnctf2020_coffer
- sharkyctf2020_give
- tamilctf2021_name
- utctf2021_resolve
- wpictf2020_dorsia1

For strict reproduction, record SHA256, architecture, `checksec` output, dynamic
loader, and libc version for every binary.

## 3. Algorithm 1: Suspicious Slice Extraction

Implementation target:

1. Extract PLT entries from the binary.
2. Match entries against `DEFAULT_DANGEROUS_FUNCTIONS`.
3. Build CFG.
4. Locate dangerous callsites.
5. Build CDG/DDG and run backward slicing.
6. Store suspicious basic-block addresses.

This scaffold currently implements steps 1-4 and a bounded CFG-predecessor
slice as a conservative substitute for step 5.

## 4. Algorithm 2: Exploitability Classification

Implementation target:

1. Run guided symbolic execution over suspicious slices.
2. Detect unconstrained states.
3. Check symbolic IP/BP.
4. Classify symbolic memory write/read actions.
5. Return vulnerability type and exploitability.

Current implementation provides reusable classification helpers and tests.

## 5. Algorithm 3: Exploit Plan and Constraint Generation

Implementation target:

1. Inventory binary resources with radare2.
2. Select strategy: Ret2Shellcode, Ret2libc, Ret2syscall, Ret2dll, Jmp2shellcode.
3. Build stack-pivot/ROP constraints.
4. Solve constraints and package exploit.
5. Execute locally to verify.

Current implementation performs inventory and strategy selection only.

## 6. Baselines

Prepare separate pinned environments for:

- AEGAngr: `https://github.com/PIG-007/AEG-ANGR`
- Zeratool: `https://github.com/ChrisTheCoolHut/Zeratool`
- BofAEG: paper reference

Run every binary three times and report median wall-clock time.

