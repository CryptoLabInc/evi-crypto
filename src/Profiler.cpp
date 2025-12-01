////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, CryptoLab, Inc.                                       //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "utils/Profiler.hpp"

#ifdef USE_PROFILE
#include <chrono>
#include <cstdint>
#include <dlfcn.h>
#include <fcntl.h>
#include <string>
#include <thread>

PERFETTO_TRACK_EVENT_STATIC_STORAGE();

Perfetto::Perfetto(const std::string &catgegory_name) {
    if (inCtgs(catgegory_name)) {
        ctg_name_ = catgegory_name;

        // read duration from env
        // trace_duration_ms_ = 0; // default : until end
        // read flush period from env
        // flush_period_ms_ = 1000;
        // read buffer size from env
        // buffer_size_kb_ = 128; // default : 128kb

        perfetto::TracingInitArgs args;
        args.backends = perfetto::kInProcessBackend;

        perfetto::Tracing::Initialize(args);

        bool registered = perfetto::TrackEvent::Register();
        if (!registered) {
            fprintf(stderr, "Cannot Register Perfetto TrackEvent! Perfetto should not work!\n");
            return;
        }

        initialized_ = true;
    } else {
        fprintf(stderr, "Invaild Perfetto Category name. Perfetto is not initialized.\n");
        initialized_ = false;
    }
}

void Perfetto::start() {
    // get current time to string

    std::time_t t = std::time(nullptr);
    // char time_string[std::size("hhmmss")];
    std::array<char, std::size("hhmmss")> time_string;
    std::strftime(time_string.data(), sizeof(time_string), "%H%M%S", std::localtime(&t));

    // example filename : category_124435.perfetto
    std::string new_file_name = ctg_name_ + "_" + std::string(time_string.data()) + ".perfetto";

    startSession(new_file_name);
}

void Perfetto::start(const std::string &trace_file_name) {
    startSession(trace_file_name);
}

void Perfetto::stop() {
    if (initialized_ && fd_ > 0) {
        perfetto::TrackEvent::Flush();
        tracing_session_->StopBlocking();
        close(fd_);
        fd_ = -1;
    }
    fprintf(stdout, "Session ended.\n");
}

void Perfetto::startSession(const std::string &trace_file_name) {
    fprintf(stdout, "Begin trace session\n");

    perfetto::TraceConfig cfg;
    if (TRACE_DURATION_MS > 0) {
        cfg.set_duration_ms(TRACE_DURATION_MS);
    }
    if (FLUSH_PERIOD_MS > 0) {
        cfg.set_flush_period_ms(FLUSH_PERIOD_MS);
    }

    auto *buffers = cfg.add_buffers();
    buffers->set_size_kb(BUFFER_SIZE_KB);
    buffers->set_fill_policy(perfetto::protos::gen::TraceConfig_BufferConfig_FillPolicy_RING_BUFFER);

    auto *ds_cfg = cfg.add_data_sources()->mutable_config();
    ds_cfg->set_name("track_event");

    auto *ds_cfg_cat = cfg.add_data_sources()->mutable_config();
    ds_cfg_cat->set_name(ctg_name_);

    fd_ = open(trace_file_name.c_str(), O_RDWR | O_CREAT | O_TRUNC, PERFETTO_FILE_MODE);
    if (fd_ <= 0) {
        fprintf(stderr, "Failed to create perfetto trace file\n");
    }

    // auto tracing_session = perfetto::Tracing::NewTrace();
    tracing_session_ = perfetto::Tracing::NewTrace();
    tracing_session_->Setup(cfg, fd_);
    fprintf(stdout, "Perfetto : StartBlocking\n");
    tracing_session_->StartBlocking();

    perfetto::ProcessTrack process_track = perfetto::ProcessTrack::Current();
    perfetto::protos::gen::TrackDescriptor desc = process_track.Serialize();
    desc.mutable_process()->set_process_name(ctg_name_);
    perfetto::TrackEvent::SetTrackDescriptor(process_track, desc);
}
#endif
