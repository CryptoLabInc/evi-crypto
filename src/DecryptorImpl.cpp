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

#include <algorithm>
#include <cassert>
#include <exception>
#include <memory>

#include "EVI/Enums.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/DecryptorImpl.hpp"
#include "EVI/impl/Parameter.hpp"
#include "nlohmann/json.hpp"
#include "utils/DebUtils.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"
#include <cmath>
#include <fstream>
#include <heaan/ntt/NTT.hpp>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

using json = nlohmann::json;

namespace evi {
namespace detail {
namespace {

constexpr deb::Size MAX_DECRYPT_SIZE = 2;

// TODO(temporary): remove once Query's internal layout is unified. IP3 (#703)
// keeps rows in typed_data_state_ (not single_blocks_), so a freshly-encrypted
// query can't be decrypted directly; flatten via serialize/deserialize for now.
Query flattenTypedQuery(const Query &query) {
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
    utils::serializeQueryTo(query, ss);
    return utils::deserializeQueryFrom(ss);
}

template <typename T>
struct NttCacheKey {
    uint64_t degree;
    T prime;

    bool operator==(const NttCacheKey &other) const noexcept {
        return degree == other.degree && prime == other.prime;
    }
};

template <typename T>
struct NttCacheKeyHash {
    std::size_t operator()(const NttCacheKey<T> &key) const noexcept {
        std::size_t seed = std::hash<uint64_t>{}(key.degree);
        seed ^= std::hash<T>{}(key.prime) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
        return seed;
    }
};

// Twiddle-factor tables are expensive to compute (O(N) modular mults).
// Cache NTT objects per (degree, prime) and word type so u32 deb paths can use
// heaan::ntt::NTT<uint32_t> without widening through the u64 implementation.
template <typename T>
heaan::ntt::NTT<T> &getCachedNtt(uint64_t degree, T prime) {
    static_assert(std::is_same_v<T, deb::u32> || std::is_same_v<T, deb::u64>,
                  "evi-ntt supports only deb::u32 and deb::u64 words");
    static std::mutex cache_mtx;
    static std::unordered_map<NttCacheKey<T>, std::shared_ptr<heaan::ntt::NTT<T>>, NttCacheKeyHash<T>> cache;
    thread_local std::unordered_map<NttCacheKey<T>, heaan::ntt::NTT<T> *, NttCacheKeyHash<T>> local_cache;

    const NttCacheKey<T> key{degree, prime};
    auto local_it = local_cache.find(key);
    if (local_it != local_cache.end()) {
        return *local_it->second;
    }

    std::lock_guard<std::mutex> lock(cache_mtx);
    auto it = cache.find(key);
    if (it == cache.end()) {
        it = cache.emplace(key, std::make_shared<heaan::ntt::NTT<T>>(degree, prime)).first;
    }
    // Safe: cache entries are process-lifetime immutable values and are never erased.
    // local_cache may therefore keep a non-owning pointer without risking dangling.
    local_cache.emplace(key, it->second.get());
    return *it->second;
}

uint64_t makeNttWarmupKey(const ConstantPreset *param) {
    const uint32_t total = param->getNumQ() + param->getNumP();
    const uint32_t count = std::min(static_cast<uint32_t>(MAX_DECRYPT_SIZE), total);
    uint64_t key = 1469598103934665603ULL;
    auto mix = [&key](uint64_t value) {
        key ^= value;
        key *= 1099511628211ULL;
    };
    mix(DEGREE);
    mix(count);
    for (uint32_t i = 0; i < count; ++i) {
        mix(deb_prime_at(param, i));
    }
    return key;
}

// NTT twiddle tables are process-wide and immutable after construction.
// Warmup creates them once; decrypt workers reuse the shared read-only tables.
// Templated on the word type so the IP3 u32-native path warms heaan::ntt::NTT<u32>
// tables (the ones it actually uses) instead of the unused u64 tables. Each T
// instantiation gets its own `warmed_params`/cache, so u32 and u64 never collide.
template <typename T = deb::u64>
void warmupNttCache(const ConstantPreset *param) {
    static std::mutex warmed_mtx;
    static std::unordered_set<uint64_t> warmed_params;

    const uint64_t key = makeNttWarmupKey(param);
    std::lock_guard<std::mutex> lock(warmed_mtx);
    if (warmed_params.find(key) != warmed_params.end()) {
        return;
    }

    const uint32_t total = param->getNumQ() + param->getNumP();
    const uint32_t count = std::min(static_cast<uint32_t>(MAX_DECRYPT_SIZE), total);
    for (uint32_t i = 0; i < count; ++i) {
        getCachedNtt<T>(DEGREE, static_cast<T>(deb_prime_at(param, i)));
    }

    warmed_params.insert(key);
}

template <typename T = deb::u64>
void warmupNttCache(const detail::Context &context) {
    warmupNttCache<T>(context->getParam().get());
}

template <typename T>
void forwardNttWithEvi(deb::PolynomialT<T> &poly, deb::Size num_polyunit) {
    num_polyunit = num_polyunit ? num_polyunit : poly.size();
    for (deb::Size i = 0; i < num_polyunit; ++i) {
        if (poly[i].isNTT()) {
            continue;
        }
        getCachedNtt<T>(static_cast<uint64_t>(poly[i].degree()), poly[i].prime()).forwardNTT(poly[i].data());
        poly[i].setNTT(deb::utils::NTTType::NEGACYCLIC, deb::utils::NTTRootType::DIRECT);
    }
}

template <typename T>
void backwardNttWithEvi(deb::PolynomialT<T> &poly) {
    for (deb::Size i = 0; i < poly.size(); ++i) {
        if (!poly[i].isNTT()) {
            continue;
        }
        getCachedNtt<T>(static_cast<uint64_t>(poly[i].degree()), poly[i].prime()).backwardNTT(poly[i].data());
        poly[i].setNTT(deb::utils::NTTType::NONNTT);
    }
}

// T-generic coeff-domain decrypt via evi-ntt. T = u64 (default deb path)
// or u32 (IP3 native result path). u64 callers deduce T from deb::Decryptor.
template <typename T>
void decryptCoeffWithEviNtt(const deb::DecryptorT<deb::PRESET_EMPTY, T> &dec, const deb::CiphertextT<T> &ctxt,
                            const deb::SecretKeyT<T> &sk, deb::CoeffMessage &msg, double scale) {
    const deb::Size num_polyunit = std::min(ctxt[0].size(), MAX_DECRYPT_SIZE);

    // 2-NTT path: forward-NTT only 'a', then compute ptxt = INTT(sk*a) + b.
    // deb's own decrypt also uses 2 NTTs (forward a + backward), skipping forward NTT
    // on b by adding b in COEFF domain at the end. This matches that complexity.
    //
    // Thread-local scratch holds ax only; bx is read directly from the matrix (no copy)
    // after INTT(sk*a). scratch_bx is reset on every call and acts as the NTT(0)=0
    // "bx" input to innerDecrypt, so it computes sk*a without the b term.
    thread_local std::vector<T> scratch_ax(MAX_DECRYPT_SIZE * DEGREE);
    thread_local std::vector<T> scratch_bx(MAX_DECRYPT_SIZE * DEGREE, 0);
    std::fill_n(scratch_bx.data(), num_polyunit * DEGREE, 0);
    for (deb::Size pj = 0; pj < num_polyunit; ++pj) {
        std::memcpy(scratch_ax.data() + pj * DEGREE, ctxt[1][pj].data(), DEGREE * sizeof(T));
    }

    deb::CiphertextT<T> ctxt_work(ctxt.preset(), static_cast<deb::Size>(num_polyunit - 1), 2);
    for (deb::Size pj = 0; pj < num_polyunit; ++pj) {
        ctxt_work[1][pj].setData(scratch_ax.data() + pj * DEGREE, DEGREE);
        ctxt_work[0][pj].setData(scratch_bx.data() + pj * DEGREE, DEGREE);
    }
    ctxt_work.setEncoding(deb::COEFF);
    ctxt_work.setNTT(deb::utils::NTTType::NONNTT);

    deb::PolynomialT<T> ax(ctxt_work[ctxt_work.numPoly() - 1]);
    ax.setSize(ctxt_work.preset(), num_polyunit);
    forwardNttWithEvi(ax, num_polyunit);

    // Tag scratch_bx as already in NTT domain (NTT(0)=0, no transform needed).
    deb::CiphertextT<T> bx_only(ctxt_work, /*others_idx=*/0);
    bx_only.setNumPolyunit(num_polyunit);
    for (deb::Size i = 0; i < bx_only.numPoly(); ++i) {
        for (deb::Size pj = 0; pj < num_polyunit; ++pj) {
            bx_only[i][pj].setNTT(deb::utils::NTTType::NEGACYCLIC, deb::utils::NTTRootType::DIRECT);
        }
    }

    // innerDecrypt(0_ntt, sk, a_ntt) = 0 + sk*a  (NTT domain)
    deb::PolynomialT<T> ptxt = dec.innerDecrypt(bx_only, sk[0], ax);
    assert(std::all_of(scratch_bx.data(), scratch_bx.data() + num_polyunit * DEGREE, [](T value) {
        return value == 0;
    }));
    // Library boundary: deb's innerDecrypt returns its NTT-domain output already
    // reduced to [0, prime), and heaan's u32 backward NTT requires inputs
    // <= 2*prime. This seam is therefore valid only while deb keeps that
    // reduction policy; a deb change that emits unreduced output would overflow
    // the backward NTT here.
    backwardNttWithEvi(ptxt);

    // Add b in COEFF domain: ptxt = sa_coeff + b_coeff (mod prime per poly-unit)
    for (deb::Size pj = 0; pj < num_polyunit; ++pj) {
        const T prime = static_cast<T>(ptxt[pj].prime());
        const T *b = ctxt[0][pj].data();
        T *sa = ptxt[pj].data();
        for (deb::Size k = 0; k < DEGREE; ++k) {
            assert(sa[k] < prime && b[k] < prime);
            sa[k] += b[k];
            if (sa[k] >= prime) {
                sa[k] -= prime;
            }
        }
    }

    dec.innerDecode(ptxt, msg, 1.0 / scale);
}

using TopKEntry = std::tuple<float, int, int>;

bool topKEntryBetter(const TopKEntry &a, const TopKEntry &b) noexcept {
    if (std::get<0>(a) != std::get<0>(b))
        return std::get<0>(a) > std::get<0>(b);
    if (std::get<1>(a) != std::get<1>(b))
        return std::get<1>(a) < std::get<1>(b);
    return std::get<2>(a) < std::get<2>(b);
}

void pushTopKEntry(std::vector<TopKEntry> &heap, const TopKEntry &entry, int k) {
    if (static_cast<int>(heap.size()) < k) {
        heap.push_back(entry);
        if (static_cast<int>(heap.size()) == k)
            std::make_heap(heap.begin(), heap.end(), topKEntryBetter);
    } else if (k > 0 && topKEntryBetter(entry, heap[0])) {
        std::pop_heap(heap.begin(), heap.end(), topKEntryBetter);
        heap.back() = entry;
        std::push_heap(heap.begin(), heap.end(), topKEntryBetter);
    }
}

std::vector<std::tuple<int, int, float>> topKEntriesToResult(std::vector<TopKEntry> heap) {
    std::sort(heap.begin(), heap.end(), topKEntryBetter);
    std::vector<std::tuple<int, int, float>> result;
    result.reserve(heap.size());
    for (auto &[score, shard, row] : heap)
        result.emplace_back(shard, row, score);
    return result;
}

struct MemBuf : std::streambuf {
    MemBuf(const char *data, std::size_t len) {
        // setg requires char*, but this MemBuf exposes only a read area.
        // No put area is configured, so streambuf operations never write through p.
        char *p = const_cast<char *>(data);
        setg(p, p, p + len);
    }
};

} // namespace

DecryptorInterface::DecryptorInterface(const Context &context) : context_(context) {}

deb::Decryptor &DecryptorInterface::debDecryptor() {
    if (!deb_dec_) {
        deb_dec_.emplace(utils::getDebPreset(context_));
    }
    return *deb_dec_;
}

deb::Decryptor32 &DecryptorInterface::debDecryptor32() {
    if (!deb_dec32_) {
        deb_dec32_.emplace(utils::getDebPreset(context_));
    }
    return *deb_dec32_;
}

Message DecryptorInterface::decrypt(const int idx, const Query &ctxt, const SecretKey &key,
                                    std::optional<double> scale) {
    throw evi::NotSupportedError("decrypt(idx, Query, SecretKey) is only available in EvalMode::RMP");
}

std::vector<std::tuple<int, int, float>>
DecryptorInterface::decryptBatchTopKParallel(const char *const *shard_blobs, const std::size_t *shard_blob_lens,
                                             std::size_t shard_count, const char *key_blob, std::size_t key_blob_len,
                                             int k, std::optional<double> scale, int n_jobs) {
    if (k < 0)
        throw std::invalid_argument("decryptBatchTopKParallel: k must be non-negative");
    if (!shard_blobs || !shard_blob_lens)
        throw std::invalid_argument("decryptBatchTopKParallel: shard blobs/lens must not be null");
    if (!key_blob || key_blob_len == 0)
        throw std::invalid_argument("decryptBatchTopKParallel: key_blob must not be null/empty");

    const int n = static_cast<int>(shard_count);
    if (n == 0 || k == 0)
        return {};

    MemBuf key_buf(key_blob, key_blob_len);
    std::istream key_is(&key_buf);
    SecretKey shared_key = makeSecKey(key_is);

    SecretKeyAccessScope key_scope(shared_key);
    const auto mode = context_->getEvalMode();
    if (mode == EvalMode::MM || mode == EvalMode::MMS || mode == EvalMode::MM32 || mode == EvalMode::MMS32) {
        // Pre-derive the shared key once so workers don't race on getOrBuild.
        // IP3 results are u32-native, so the u32 root embedding is the one the
        // per-shard decrypt actually uses — deriving the u64 key here would be
        // thrown away and pays a full key-gen NTT per call for nothing.
        const auto deb_preset = utils::getDebPreset(context_);
        if (context_->getParam()->getPreset() == evi::ParameterPreset::IP3) {
            (void)shared_key->getDirectRootDebSecKey32(deb_preset);
        } else {
            (void)shared_key->getDirectRootDebSecKey(deb_preset);
        }
    }

    const int maxWorkers = n <= 1 ? 1 : std::max(1, (n + 1) / 2);
    const int workers = std::max(1, std::min({n_jobs, n, maxWorkers}));

    auto processShard = [&](const Decryptor &worker_dec, int i, std::vector<TopKEntry> &heap) {
        MemBuf shard_buf(shard_blobs[i], shard_blob_lens[i]);
        std::istream sin(&shard_buf);
        SearchResult shard = utils::deserializeResultFrom(sin);

        Message msg = worker_dec->decrypt(shard, shared_key, /*is_score=*/true, scale);

        const int n_scores = std::min(static_cast<int>(shard->ip_data->n), static_cast<int>(msg.size()));
        for (int j = 0; j < n_scores; ++j)
            pushTopKEntry(heap, TopKEntry{msg[j], i, j}, k);
    };

    std::vector<std::vector<TopKEntry>> workerHeaps(workers);
    for (auto &heap : workerHeaps)
        heap.reserve(static_cast<std::size_t>(k) + 1);

    if (workers == 1) {
        Decryptor worker_dec = makeDecryptor(context_);
        for (int i = 0; i < n; ++i)
            processShard(worker_dec, i, workerHeaps[0]);
    } else {
        std::vector<std::thread> threads;
        threads.reserve(workers);
        std::once_flag errFlag;
        std::exception_ptr firstErr;

        const int shardsPer = (n + workers - 1) / workers;
        for (int w = 0; w < workers; ++w) {
            const int begin = w * shardsPer;
            const int end = std::min(begin + shardsPer, n);
            if (begin >= end)
                break;

            threads.emplace_back([&, w, begin, end]() {
                try {
                    Decryptor worker_dec = makeDecryptor(context_);
                    for (int i = begin; i < end; ++i)
                        processShard(worker_dec, i, workerHeaps[w]);
                } catch (...) {
                    std::call_once(errFlag, [&]() {
                        firstErr = std::current_exception();
                    });
                }
            });
        }

        for (auto &t : threads)
            if (t.joinable())
                t.join();
        if (firstErr)
            std::rethrow_exception(firstErr);
    }

    std::vector<TopKEntry> merged;
    merged.reserve(static_cast<std::size_t>(k) + 1);
    for (auto &wh : workerHeaps) {
        for (const auto &entry : wh)
            pushTopKEntry(merged, entry, k);
    }

    return topKEntriesToResult(std::move(merged));
}

DecryptorFLAT::DecryptorFLAT(const Context &context) : DecryptorInterface(context) {}
DecryptorRMP::DecryptorRMP(const Context &context) : DecryptorFLAT(context) {}
DecryptorMM::DecryptorMM(const Context &context) : DecryptorInterface(context) {
    // IP3 decrypts in u32-native space; warm the u32 twiddle tables it uses
    // rather than the u64 tables that the IP3 decrypt loop never touches.
    if (context->getParam()->getPreset() == evi::ParameterPreset::IP3) {
        warmupNttCache<u32>(context);
        (void)debDecryptor32();
    } else {
        warmupNttCache(context);
    }
}

/**
 * DecryptorFLAT
 */
Message DecryptorFLAT::decrypt(const SearchResult ip_res, std::istream &key_stream, bool is_score,
                               std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(context_);
    key->loadSecKey(key_stream);
    return decrypt(ip_res, key, is_score, scale);
}

Message DecryptorFLAT::decrypt(const SearchResult ip_res, const std::string &key_path, bool is_score,
                               std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(key_path);
    return decrypt(ip_res, key, is_score, scale);
}

Message DecryptorFLAT::decrypt(const SearchResult ip_res, const SecretKey &key, bool is_score,
                               std::optional<double> scale) {
    if (!key->sec_loaded_) {
        throw evi::DecryptionError("Secret key is not loaded to DecryptorImpl!");
    }
    SecretKeyAccessScope key_access(key);
    auto &ctxt = ip_res->ip_data;
    // Step 4: ctxt is shared_ptr<IDataBase>; only IData<u64> exists at this step.
    auto *ctxt_u64 = asU64Data(ctxt.get());
    if (!ctxt_u64->getPoly(0, 0).size()) {
        throw evi::DecryptionError("Invalid Ciphertext type is given");
    }

    Message res;
    double scale_factor = std::pow(2, context_->getParam()->getScaleFactor() * (is_score ? 2 : 1));
    if (scale.has_value()) {
        scale_factor = scale.value();
    }

    deb::CoeffMessage buf(DEGREE);
    for (u64 offset = 0; offset < ctxt_u64->getPoly(0, 0).size(); offset += DEGREE) {
        // Score extraction emits one float per logical item (ctxt->n total);
        // once all items are covered the remaining polynomial chunks are empty
        // padding, so skip them before the (expensive) decrypt below.
        if (is_score && context_->getEvalMode() != EvalMode::SINGLE && offset >= ctxt->n)
            break;

        if (!ctxt->getLevel()) {
            deb::Ciphertext deb_ctxt = utils::convertPointerToDebCipher(
                context_, ctxt_u64->getPoly(1, 0).data() + offset, ctxt_u64->getPoly(0, 0).data() + offset);
            debDecryptor().decrypt(deb_ctxt, key->getDebSecKey(), buf, scale_factor);
        } else {
            deb::Ciphertext deb_ctxt = utils::convertPointerToDebCipher(
                context_, ctxt_u64->getPoly(1, 0).data() + offset, ctxt_u64->getPoly(0, 0).data() + offset,
                ctxt_u64->getPoly(1, 1).data() + offset, ctxt_u64->getPoly(0, 1).data() + offset);
            debDecryptor().decrypt(deb_ctxt, key->getDebSecKey(), buf, scale_factor);
        }

        if (is_score) {
            const u64 items_per_ctxt = context_->getItemsPerCtxt();
            const u64 pad_rank = context_->getPadRank();
            float tmp;
            if (context_->getEvalMode() == EvalMode::SINGLE) {
                res.push_back(buf[pad_rank - 1]);
            } else {
                // Each DEGREE-coefficient polynomial chunk holds up to DEGREE items.
                // Item j maps to buf[(j%items_per_ctxt)*pad_rank + j/items_per_ctxt];
                // use chunk-relative j_local so the index stays within [0, DEGREE).
                // The trailing-empty-chunk early-exit is handled at the top of the
                // offset loop, so here offset < ctxt->n is guaranteed.
                const u64 n_in_chunk = std::min(static_cast<u64>(DEGREE), ctxt->n - offset);
                for (u64 j_local = 0; j_local < n_in_chunk; ++j_local) {
                    tmp = buf[(j_local % items_per_ctxt) * pad_rank + j_local / items_per_ctxt];
                    res.push_back(tmp);
                }
            }
        } else {
            for (u64 j = 0; j < DEGREE; ++j) {
                res.push_back(buf[j]);
            }
        }
    }
    return res;
}

Message DecryptorFLAT::decrypt(const Query &ctxt, std::istream &key_stream, std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(context_);
    key->loadSecKey(key_stream);
    return decrypt(ctxt, key, scale);
}

Message DecryptorFLAT::decrypt(const Query &ctxt, const std::string &key_path, std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(key_path);
    return decrypt(ctxt, key, scale);
}

Message DecryptorFLAT::decrypt(const Query &ctxt, const SecretKey &key, std::optional<double> scale) {
    if (!key->sec_loaded_) {
        throw evi::DecryptionError("Secret key is not loaded to DecryptorImpl!");
    }
    if (ctxt.getTypedDataState()) {
        return decrypt(flattenTypedQuery(ctxt), key, scale);
    }
    SecretKeyAccessScope key_access(key);

    Message res(DEGREE, 0.0f);
    double scale_factor = std::pow(2, context_->getParam()->getScaleFactor());
    if (scale.has_value()) {
        scale_factor = scale.value();
    }

    deb::CoeffMessage tmp_msg(DEGREE);
    const auto deb_preset = utils::getDebPreset(context_);
    for (int i = 0; i < ctxt.size(); i++) {
        if (ctxt[i]->isU32()) {
            deb::Ciphertext32 deb_ctxt =
                ctxt[i]->getLevel() == 0
                    ? utils::convertPointerToDebCipher<u32>(context_, ctxt[i]->getPoly32(1, 0).data(),
                                                            ctxt[i]->getPoly32(0, 0).data(), nullptr, nullptr)
                    : utils::convertPointerToDebCipher<u32>(
                          context_, ctxt[i]->getPoly32(1, 0).data(), ctxt[i]->getPoly32(0, 0).data(),
                          ctxt[i]->getPoly32(1, 1).data(), ctxt[i]->getPoly32(0, 1).data());
            debDecryptor32().decrypt(deb_ctxt, key->getDebSecKey32(deb_preset), tmp_msg, scale_factor);
        } else if (ctxt[i]->getLevel() == 0) {
            deb::Ciphertext deb_ctxt = utils::convertPointerToDebCipher(context_, ctxt[i]->getPoly(1, 0).data(),
                                                                        ctxt[i]->getPoly(0, 0).data());
            debDecryptor().decrypt(deb_ctxt, key->getDebSecKey(), tmp_msg, scale_factor);
        } else {
            deb::Ciphertext deb_ctxt =
                utils::convertPointerToDebCipher(context_, ctxt[i]->getPoly(1, 0).data(), ctxt[i]->getPoly(0, 0).data(),
                                                 ctxt[i]->getPoly(1, 1).data(), ctxt[i]->getPoly(0, 1).data());
            debDecryptor().decrypt(deb_ctxt, key->getDebSecKey(), tmp_msg, scale_factor);
        }

        u64 size = ctxt[i]->dim;
        u64 ctxt_dim = isPowerOfTwo(size) ? size : nextPowerOfTwo(size);

        u64 pad_offset = ctxt_dim - ((i + 1 == ctxt.size()) ? (ctxt[i]->show_dim % ctxt[i]->dim) : 0);
        if (ctxt[i]->encode_type == EncodeType::ITEM) {
            // std::copy_n(tmp_msg.begin(), pad_offset, res.begin() + size * i);
            for (u64 j = 0; j < pad_offset; ++j) {
                res[size * i + j] = static_cast<float>(tmp_msg[j]);
            }
        } else {
            // std::reverse_copy(tmp_msg.begin() + size - pad_offset, tmp_msg.begin() + size, res.begin() + size * i);
            for (u64 j = 0; j < pad_offset; ++j) {
                res[size * i + j] = static_cast<float>(tmp_msg[size - 1 - j]);
            }
        }
    }

    return res;
}

/**
 * DecryptorRMP
 */
Message DecryptorRMP::decrypt(const int idx, const Query &ctxt, const SecretKey &key, std::optional<double> scale) {
    if (!key->sec_loaded_) {
        throw evi::DecryptionError("Secret key is not loaded to DecryptorInterface!");
    }
    SecretKeyAccessScope key_access(key);
    Message res(DEGREE, 0.0f);
    double scale_factor = std::pow(2, context_->getParam()->getScaleFactor());
    if (scale.has_value()) {
        scale_factor = scale.value();
    }

    deb::CoeffMessage tmp_msg(DEGREE);
    const auto deb_preset = utils::getDebPreset(context_);
    for (int i = 0; i < ctxt.size(); i++) {
        if (ctxt[i]->isU32()) {
            deb::Ciphertext32 deb_ctxt =
                ctxt[i]->getLevel() == 0
                    ? utils::convertPointerToDebCipher<u32>(context_, ctxt[i]->getPoly32(1, 0).data(),
                                                            ctxt[i]->getPoly32(0, 0).data(), nullptr, nullptr)
                    : utils::convertPointerToDebCipher<u32>(
                          context_, ctxt[i]->getPoly32(1, 0).data(), ctxt[i]->getPoly32(0, 0).data(),
                          ctxt[i]->getPoly32(1, 1).data(), ctxt[i]->getPoly32(0, 1).data());
            debDecryptor32().decrypt(deb_ctxt, key->getDebSecKey32(deb_preset), tmp_msg, scale_factor);
        } else if (ctxt[i]->getLevel() == 0) {
            deb::Ciphertext deb_ctxt = utils::convertPointerToDebCipher(context_, ctxt[i]->getPoly(1, 0).data(),
                                                                        ctxt[i]->getPoly(0, 0).data());
            debDecryptor().decrypt(deb_ctxt, key->getDebSecKey(), tmp_msg, scale_factor);
        } else {
            deb::Ciphertext deb_ctxt =
                utils::convertPointerToDebCipher(context_, ctxt[i]->getPoly(1, 0).data(), ctxt[i]->getPoly(0, 0).data(),
                                                 ctxt[i]->getPoly(1, 1).data(), ctxt[i]->getPoly(0, 1).data());
            debDecryptor().decrypt(deb_ctxt, key->getDebSecKey(), tmp_msg, scale_factor);
        }

        u64 size = ctxt[i]->dim;
        u64 ctxt_dim = isPowerOfTwo(size) ? size : nextPowerOfTwo(size);

        u64 pad_offset = ctxt_dim - ((i + 1 == ctxt.size()) ? (ctxt[i]->show_dim % ctxt[i]->dim) : 0);
        if (ctxt[i]->encode_type == EncodeType::ITEM) {
            // std::copy_n(tmp_msg.begin(), pad_offset, res.begin() + size * i);
            for (u64 j = 0; j < pad_offset; ++j) {
                res[size * i + j] = static_cast<float>(tmp_msg[j + idx * size]);
            }
        } else {
            // std::reverse_copy(tmp_msg.begin() + size - pad_offset, tmp_msg.begin() + size, res.begin() + size * i);
            for (u64 j = 0; j < pad_offset; ++j) {
                res[size * i + j] = static_cast<float>(tmp_msg[size - 1 - j]);
            }
        }
    }

    return res;
}

/**
 * DecryptorMM
 */
Message DecryptorMM::decrypt(const SearchResult ip_res, std::istream &key_stream, bool is_score,
                             std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(context_);
    key->loadSecKey(key_stream);
    return decrypt(ip_res, key, is_score, scale);
}

Message DecryptorMM::decrypt(const SearchResult ip_res, const std::string &key_path, bool is_score,
                             std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(key_path);
    return decrypt(ip_res, key, is_score, scale);
}

Message DecryptorMM::decrypt(const SearchResult ctxts, const evi::detail::SecretKey &seckey, bool is_score,
                             std::optional<double> scale) {
    SecretKeyAccessScope key_access(seckey);
    auto &matrix = ctxts->ip_data;
    // IP3 produces a u32-native result (IData<u32>); all other presets produce
    // IData<u64>. Dispatch on the element width so we never asU64Data a u32 matrix.
    const bool result_is_u32 = matrix->isU32();
    const bool has_data = result_is_u32 ? (asU32Data(matrix.get())->getPoly(0, 0).size() != 0)
                                        : (asU64Data(matrix.get())->getPoly(0, 0).size() != 0);
    if (!has_data) {
        throw evi::DecryptionError("Invalid Ciphertext type is given");
    }

    const int level = matrix->getLevel();

    // Detect base conversion: IData::preset holds the prime space the
    // ciphertext's coefficients are in (set by compute after base conversion,
    // RUNTIME if no conversion). ctx_preset is the encryption preset —
    // the Decryptor context must always match what was used to encrypt.
    const auto ctx_preset = context_->getParam()->getPreset();
    const auto res_preset = matrix->preset;
    const bool is_base_converted = res_preset != ParameterPreset::RUNTIME && res_preset != ctx_preset;

    // Auto-compute scale bits for the decoded plaintext.
    //
    // Two cases:
    //   1. Rescale-only (or level > 0): use context SCALE_FACTOR (existing path).
    //   2. Base-converted: base conversion multiplies raw values by
    //      Q_target / (Q_ctx * P_ctx) instead of rescaling by P_ctx.
    //      Result scale = DB_SCALE + log2(Q_target / (Q_ctx * P_ctx)) + QUERY_SCALE.
    double delta = 0.0;
    double scale_bits = 0.0;

    if (is_base_converted) {
        const auto res_param = setPreset(res_preset);
        const double q_target = static_cast<double>(res_param->getQ(0));
        const double q_ctx = static_cast<double>(context_->getParam()->getQ(0));
        const double p_ctx = static_cast<double>(deb_prime_at(context_->getParam(), 1));
        const double db_scale = context_->getParam()->getDBScaleFactor();
        const double query_scale = context_->getParam()->getQueryScaleFactor();
        scale_bits = db_scale + std::log2(q_target / (q_ctx * p_ctx)) + query_scale;
    } else if ((ctx_preset == evi::ParameterPreset::IP1 || ctx_preset == evi::ParameterPreset::IP2 ||
                ctx_preset == evi::ParameterPreset::IP3) &&
               level == 0) {
        scale_bits = context_->getParam()->getScaleFactor();
    } else {
        scale_bits = context_->getParam()->getScaleFactor() * 2;
    }
    delta = scale.value_or(std::pow(2.0, scale_bits));

    // For base-converted results, decrypt with the target preset's deb
    // decryptor so that b + s*a is computed mod the correct modulus.
    std::optional<deb::Decryptor> bc_dec;
    const deb::SecretKey *bc_sk = nullptr;
    const deb::SecretKey *direct_sk = nullptr;

    if (is_base_converted) {
        const auto deb_preset = utils::getDebPreset(res_preset);
        bc_dec.emplace(deb_preset);
        bc_sk = &seckey->getDirectRootDebSecKey(deb_preset);
        warmupNttCache(setPreset(res_preset).get());
    } else if (result_is_u32) {
        // IP3 u32-native path: the u32 root key and u32 NTT tables are derived
        // in the loop below. Warm the u32 twiddle tables here (not the u64 ones,
        // which this path never touches) and skip the unused u64 key derivation.
        warmupNttCache<u32>(context_);
    } else {
        const auto deb_preset = utils::getDebPreset(context_);
        direct_sk = &seckey->getDirectRootDebSecKey(deb_preset);
        warmupNttCache(context_);
    }

    const size_t rows = static_cast<size_t>(matrix->dim);
    size_t item_count = ctxts.getTotalItemCount() / DEGREE;
    if (!item_count) {
        item_count = static_cast<size_t>(matrix->n);
    }

    Message msgs(rows * item_count * DEGREE, 0.0f);
    deb::CoeffMessage dmsg(DEGREE);

    // IP3 native-u32 result: decrypt the u32 limbs directly with deb::Decryptor32
    // (no widen). IP3 results stay in IP3 prime space, so they are never
    // base-converted — only the direct path is needed here.
    if (result_is_u32) {
        auto *m32 = asU32Data(matrix.get());
        const auto deb_preset = utils::getDebPreset(context_);
        auto &dec32 = debDecryptor32();
        const auto &sk32 = seckey->getDirectRootDebSecKey32(deb_preset);
        u32 *a0 = m32->getPolyData(1, 0);
        u32 *b0 = m32->getPolyData(0, 0);
        u32 *a1 = level ? m32->getPolyData(1, 1) : nullptr;
        u32 *b1 = level ? m32->getPolyData(0, 1) : nullptr;
        for (size_t row = 0; row < rows; ++row) {
            for (size_t item = 0; item < item_count; ++item) {
                const size_t off = (item * rows + row) * DEGREE;
                deb::Ciphertext32 deb_ctxt = utils::convertPointerToDebCipher<u32>(
                    context_, a0 + off, b0 + off, a1 ? a1 + off : nullptr, b1 ? b1 + off : nullptr, false);
                decryptCoeffWithEviNtt<u32>(dec32, deb_ctxt, sk32, dmsg, delta);
                float *dst = msgs.data() + (row * item_count + item) * DEGREE;
                for (u64 k = 0; k < DEGREE; ++k) {
                    dst[k] = static_cast<float>(dmsg[k]);
                }
            }
        }
        return msgs;
    }

    auto *matrix_u64 = asU64Data(matrix.get());
    u64 *a_lvl0_base = matrix_u64->getPolyData(1, 0);
    u64 *b_lvl0_base = matrix_u64->getPolyData(0, 0);
    u64 *a_lvl1_base = level ? matrix_u64->getPolyData(1, 1) : nullptr;
    u64 *b_lvl1_base = level ? matrix_u64->getPolyData(0, 1) : nullptr;

    for (size_t row = 0; row < rows; ++row) {
        for (size_t item = 0; item < item_count; ++item) {
            const size_t poly_idx = item * rows + row;
            u64 *a_lvl0 = a_lvl0_base + poly_idx * DEGREE;
            u64 *b_lvl0 = b_lvl0_base + poly_idx * DEGREE;
            u64 *a_lvl1 = level ? a_lvl1_base + poly_idx * DEGREE : nullptr;
            u64 *b_lvl1 = level ? b_lvl1_base + poly_idx * DEGREE : nullptr;

            if (is_base_converted) {
                deb::Ciphertext deb_ctxt =
                    utils::convertPointerToDebCipherWithPreset(res_preset, a_lvl0, b_lvl0, false);
                decryptCoeffWithEviNtt(*bc_dec, deb_ctxt, *bc_sk, dmsg, delta);
            } else {
                deb::Ciphertext deb_ctxt =
                    utils::convertPointerToDebCipher(context_, a_lvl0, b_lvl0, a_lvl1, b_lvl1, false);
                decryptCoeffWithEviNtt(debDecryptor(), deb_ctxt, *direct_sk, dmsg, delta);
            }

            float *dst = msgs.data() + (row * item_count + item) * DEGREE;
            for (u64 k = 0; k < DEGREE; ++k) {
                dst[k] = static_cast<float>(dmsg[k]);
            }
        }
    }
    return msgs;
}

Message DecryptorMM::decrypt(const Query &ctxts, std::istream &key_stream, std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(context_);
    key->loadSecKey(key_stream);
    return decrypt(ctxts, key, scale);
}

Message DecryptorMM::decrypt(const Query &ctxts, const std::string &key_path, std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(key_path);
    return decrypt(ctxts, key, scale);
}

Message DecryptorMM::decrypt(const Query &ctxts, const SecretKey &seckey, std::optional<double> scale) {
    if (ctxts.getTypedDataState()) {
        return decrypt(flattenTypedQuery(ctxts), seckey, scale);
    }
    SecretKeyAccessScope key_access(seckey);
    const u64 rows = static_cast<u64>(ctxts.size());
    if (!rows) {
        throw evi::InvalidInputError("Matrix query is empty");
    }

    const u64 inner_count = static_cast<u64>(ctxts.getInnerItemCount());
    const u64 cols = inner_count ? inner_count : static_cast<u64>(DEGREE);
    const u32 msg_dim = context_->getShowRank();
    Message msgs(cols * msg_dim, 0.0f);

    double delta = 0.0;
    if (scale.has_value()) {
        delta = scale.value();
    } else if (ctxts[0]->encode_type == EncodeType::ITEM) {
        // MM bulk ITEM encryption uses the DB scale for level-1 ciphertexts.
        delta = std::pow(2.0, context_->getParam()->getDBScaleFactor());
    } else {
        delta = std::pow(2.0, context_->getParam()->getScaleFactor());
    }

    deb::CoeffMessage tmp_msg(DEGREE);
    const auto deb_preset = utils::getDebPreset(context_);
    // Derive the root key embedding and warm the NTT tables on first use of each
    // width. IP3 blocks are u32-native, so this avoids paying the u64 key-gen NTT
    // and u64 twiddle-table warmup that the u32 decrypt loop never touches.
    const deb::SecretKey *direct_sk = nullptr;
    const deb::SecretKey32 *direct_sk32 = nullptr;
    const u64 stride = msg_dim;
    const u64 active_rows = std::min<u64>(rows, stride);
    const u64 active_cols = std::min<u64>(cols, static_cast<u64>(DEGREE));

    for (u64 row = 0; row < active_rows; ++row) {
        const auto &block = ctxts[row];
        if (!block) {
            throw evi::InvalidInputError("Matrix query contains null single block");
        }

        if (block->isU32()) {
            deb::Ciphertext32 deb_ctxt =
                block->getLevel() == 0
                    ? utils::convertPointerToDebCipher<u32>(context_, block->getPoly32(1, 0).data(),
                                                            block->getPoly32(0, 0).data(), nullptr, nullptr, false)
                    : utils::convertPointerToDebCipher<u32>(
                          context_, block->getPoly32(1, 0).data(), block->getPoly32(0, 0).data(),
                          block->getPoly32(1, 1).data(), block->getPoly32(0, 1).data(), false);
            if (!direct_sk32) {
                direct_sk32 = &seckey->getDirectRootDebSecKey32(deb_preset);
                warmupNttCache<u32>(context_);
            }
            decryptCoeffWithEviNtt<u32>(debDecryptor32(), deb_ctxt, *direct_sk32, tmp_msg, delta);
        } else {
            deb::Ciphertext deb_ctxt =
                block->getLevel() == 0
                    ? utils::convertPointerToDebCipher<u64>(context_, block->getPoly(1, 0).data(),
                                                            block->getPoly(0, 0).data(), nullptr, nullptr, false)
                    : utils::convertPointerToDebCipher(context_, block->getPoly(1, 0).data(),
                                                       block->getPoly(0, 0).data(), block->getPoly(1, 1).data(),
                                                       block->getPoly(0, 1).data(), false);
            if (!direct_sk) {
                direct_sk = &seckey->getDirectRootDebSecKey(deb_preset);
                warmupNttCache(context_);
            }
            decryptCoeffWithEviNtt(debDecryptor(), deb_ctxt, *direct_sk, tmp_msg, delta);
        }

        for (u64 col = 0; col < active_cols; ++col) {
            msgs[col * stride + row] = static_cast<float>(tmp_msg[col]);
        }
    }
    return msgs;
}

Decryptor makeDecryptor(const Context &context) {
    if (context->getEvalMode() == EvalMode::FLAT) {
        return Decryptor(std::make_shared<DecryptorFLAT>(context));
    } else if (context->getEvalMode() == EvalMode::SINGLE) {
        return Decryptor(std::make_shared<DecryptorFLAT>(context));
    } else if (context->getEvalMode() == EvalMode::RMP) {
        return Decryptor(std::make_shared<DecryptorRMP>(context));
    } else if (context->getEvalMode() == EvalMode::MM || context->getEvalMode() == EvalMode::MMS ||
               context->getEvalMode() == EvalMode::MM32 || context->getEvalMode() == EvalMode::MMS32) {
        return Decryptor(std::make_shared<DecryptorMM>(context));
    } else {
        throw InvalidAccessError("invalid access");
    }
}
} // namespace detail
} // namespace evi
