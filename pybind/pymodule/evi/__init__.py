#////////////////////////////////////////////////////////////////////////////////
#//                                                                            //
#//  Copyright (C) 2025, CryptoLab, Inc.                                       //
#//                                                                            //
#//  Licensed under the Apache License, Version 2.0 (the "License");           //
#//  you may not use this file except in compliance with the License.          //
#//  You may obtain a copy of the License at                                   //
#//                                                                            //
#//     http://www.apache.org/licenses/LICENSE-2.0                             //
#//                                                                            //
#//  Unless required by applicable law or agreed to in writing, software       //
#//  distributed under the License is distributed on an "AS IS" BASIS,         //
#//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
#//  See the License for the specific language governing permissions and       //
#//  limitations under the License.                                            //
#//                                                                            //
#////////////////////////////////////////////////////////////////////////////////

import importlib.util
import os
import ctypes
import sys
import glob

lib_path = os.path.dirname(__file__)

current_ld_library_path = os.environ.get('LD_LIBRARY_PATH', '')
if lib_path not in current_ld_library_path.split(':'):
    os.environ['LD_LIBRARY_PATH'] = lib_path + ':' + current_ld_library_path

## Load the file if it exists
## libHEaaN must be loaded before libEVI
libs_to_load = ["lib/libHEaaN.so", "lib/libEVI.so", "lib64/libEVI.so", "lib/libHEaaN.dylib", "lib/libEVI.dylib", "lib64/libEVI.dylib"]
for lib in libs_to_load:
    lib_full_path = os.path.join(lib_path, lib)
    if os.path.exists(lib_full_path):
        try:
            ctypes.CDLL(lib_full_path, mode=ctypes.RTLD_GLOBAL)
        except OSError as e:
            print(f"{lib} not loaded", file=sys.stderr)
            raise
so_files = glob.glob(os.path.join(lib_path, "evi*.so"))

if not so_files:
    raise ImportError("No evi module found in {lib_path}")
else:
    so_file = so_files[0]
    spec = importlib.util.spec_from_file_location("evi", so_file)
    if spec is None:
        raise ImportError(f"Could not create spec for {so_file}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    globals().update({k: getattr(mod, k) for k in dir(mod) if not k.startswith('__')})
