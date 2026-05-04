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

#pragma once

#include <cstdarg>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace evi {

class EviError : public std::runtime_error {
public:
    explicit EviError(const std::string &message) : std::runtime_error(message) {}

    template <typename... Args, std::enable_if_t<(sizeof...(Args) >= 2), int> = 0>
    EviError(Args &&...args) : std::runtime_error(concat(std::forward<Args>(args)...)) {}

    virtual const char *errorName() const {
        return "EviError";
    }

    virtual const char *auditCode() const noexcept {
        return "";
    }

    const char *what() const noexcept override {
        static std::string full_message;
        std::ostringstream oss;
        oss << "[" << errorName() << "] " << std::runtime_error::what();
        full_message = oss.str();
        return full_message.c_str();
    }

private:
    template <typename... Args>
    static std::string concat(Args... args) {
        std::ostringstream oss;
        (oss << ... << args);
        return oss.str();
    }
};

class EncryptionError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "EncryptionError";
    }
};

class FileNotFoundError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "FileNotFoundError";
    }
};

class KeyNotLoadedError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "KeyNotLoadedError";
    }
};

class DecryptionError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "DecryptionError";
    }
};

class NotSupportedError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "NotSupportedError";
    }
};

class InvalidInputError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "InvalidInputError";
    }
};

class AuditCodedError : public InvalidInputError {
public:
    AuditCodedError(std::string code, const std::string &message)
        : InvalidInputError(message), code_(std::move(code)) {}

    const char *errorName() const override {
        return "InvalidInputError";
    }

    const char *auditCode() const noexcept override {
        return code_.c_str();
    }

private:
    std::string code_;
};

class InvalidAccessError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "InvalidAccessError";
    }
};

} // namespace evi
