#!/bin/bash
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

conda_path=$(which conda)

if [ -z "$conda_path" ]; then
    echo "Conda executable not found"
    exit 1
fi

# Extract the directory path from the Conda executable path
conda_dir=$(dirname "$conda_path")

# Construct the path to the Conda environments directory
conda_envs_path=$(realpath $conda_dir/../envs)

# Print the path to the Conda environments directory
echo $conda_envs_path
