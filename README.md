# evi-crypto

`evi-crypto` is a homomorphic encryption module designed to execute vector search queries securely over encrypted data.

### Build
```sh
cmake -S . -B build
cmake --build build
```

### CMake Options

| Option | Default | Description |
|---|---|---|
| `BUILD_TEST` | `ON` | Build unit tests under `test/` and add them to `ctest`. |
| `BUILD_EXAMPLE` | `ON` | Build examples under `examples/` (e.g., `keygen`). |
| `BUILD_YUBIHSM` | `OFF` | Enable YubiHSM integration for secret key protection (only effective when HEaaN is enabled). |
| `BUILD_WITH_VALGRIND` | `ON` | Enable constant-time sampler checks with Valgrind instrumentation. |
| `BUILD_AS_STATIC` | `ON` | Build EVI as a static library; set `OFF` for a shared library. |
| `USE_PROFILE` | `OFF` | Enable Perfetto-based profiling and link the `perfetto` SDK. |
| `BUILD_PYTHON` | `OFF` | Build Python wheels/bindings. |
| `BUILD_C_API` | `OFF` | Build C wrapper API. |
Note: The main EVI library includes key generation and encryption/decryption modules; separate component libraries are not emitted.

Notes
- When `BUILD_PYTHON=ON`, several options are forced to packaging-safe values (e.g., `BUILD_TEST=OFF`, `BUILD_EXAMPLE=OFF`, `BUILD_AS_STATIC=OFF`). See `CMakeLists.txt` for details.
- The project fetches externals using CPM; if your environment requires credentials, set `GITHUB_TOKEN` in the environment for private dependencies.


### Release using pybind
```
$ pip wheel . --no-deps -w dist -Cbuild-dir=build
$ pip install dist/evi-0.1.0-cp312-cp312-linux_x86_64.whl
$ pytest pybind/test/ ## for test
```

## Documentation
You can generate the documentation using the command below, and then open `./docs/html/index.html`.
```
$ doxygen Doxyfile
```

### License
deb is licensed under the Apache License 2.0, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions.

See the LICENSE file for more details.
