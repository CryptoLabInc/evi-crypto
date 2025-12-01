# Memory Check Script

This directory contains a script to help you automatically check for memory leaks in the example binaries after building the project.

## How to Use

After building the project (see the main repository README for build instructions), run:

```sh
bash run-memory-check.sh
```

## What does `run-memory-check.sh` do?
- Searches for all executable files in `../build/examples/` whose names start with `db` or `query`.
- For each executable, generates two random arguments: `dim` (the dimension of the vector) and `size` (the number of vectors), and runs the program with them.
- Runs [valgrind](https://valgrind.org/) on each executable to check for memory leaks. If any leak is detected, the script stops immediately.
- If [compute-sanitizer](https://docs.nvidia.com/cuda/compute-sanitizer/) (formerly cuda-memcheck) is installed and the executable is not a CPU-only binary, it also runs GPU memory checks.
- If compute-sanitizer is not installed, it skips the GPU memory check and prints a message.

- This script helps you ensure that your code is free from memory leaks on both CPU and GPU (if applicable).
