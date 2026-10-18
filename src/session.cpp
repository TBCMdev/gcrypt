#include "session.hpp"
#include "util.hpp"
#include "store.hpp"
#include "algorithms.hpp"
#include <algorithm>
#include <ranges>

namespace gcrypt::session
{

    messaging_session::messaging_session(const std::string& recipientId, const xckey& SK, const xckey& PeerDHPublicKey, const key<32>& masterSecretKey) :
        identifier(recipientId), rstate
        {
            .remoteIdentityKey = SK,
            .rootKey           = masterSecretKey,
            .remoteRatchetKey  = PeerDHPublicKey
        }
    {
        dhstep();
    }
    messaging_session::messaging_session(const std::string& recipientId, const xckey& SK, const xckeypair& LRK, const key<32>& masterSecretKey) :
        identifier(recipientId), rstate
        {
            .remoteIdentityKey = SK,
            .rootKey = masterSecretKey,
            .localRatchetKey = LRK
        }
    {
        // master secret already derived and received.
    }
    util::convert_result<skipped_message_key> skipped_message_key::from_bytes(const fixed_bytespan& from)
    {
        if (from.size() < typebytes(skipped_message_key))
            return convert_error<fixed_bytespan, skipped_message_key>("Bytearray not long enough for sizeof(skipped_message_key)");
        size_t offset = 0;

        xckey rpk;
        key<32> mk;
        uint32_t sn;

        const std::span<const uint8_t> span(from.begin(), from.end());

        util::load_keyb(span, rpk, offset);
        util::load_keyb(span, mk,  offset += varbytes(rpk));
        std::memcpy(&sn, span.data() + offset + varbytes(mk), varbytes(sn));

        return skipped_message_key{rpk, mk, sn};
    }

    bytedata skipped_message_key::to_bytes() const
    {
        bytedata data;
        data.resize(typebytes(skipped_message_key));

        size_t off = util::write_key_bytes(data, 0, ratchetPublicKey, messageKey);
        
        std::ranges::copy(util::bytes(sequenceNumber), data.begin() + off);

        return data;
    }
    util::convert_result<messaging_session> messaging_session::from_bytes(const std::string& recipientId, const fixed_bytespan& from)
    {
        if (from.size() < typebytes(messaging_session))
            return convert_error<fixed_bytespan, messaging_session>("Bytearray not long enough for sizeof(messaging_session).");

        size_t offset = 0;

        xckey rik;
        key<32> rk, sck, rck;
        xckeypair lrk;
        xckey rrk;
        uint32_t ss, rs, pcl;
        uint32_t sc; // skipped count
        std::vector<skipped_message_key> smks;

        const std::span<const uint8_t> span(from.begin(), from.end());

        // for security, we should use load_keyb_s (load key bytes safe) to zero the memory after loading from the span.
        // however the current parent implementation expects a const span, so we cannot modify the data.
        util::load_keyb(span, rik,         offset);
        util::load_keyb(span, rk,          offset += varbytes(rik));
        util::load_keyb(span, sck,         offset += varbytes(rk));
        util::load_keyb(span, rck,         offset += varbytes(sck));
        util::load_keyb(span, lrk.Public,  offset += varbytes(rck));
        util::load_keyb(span, lrk.Private, offset += varbytes(lrk.Public));
        util::load_keyb(span, rrk,         offset += varbytes(lrk.Private));
        
        offset += varbytes(lrk.Private);

        std::memcpy(&ss,  span.data() + offset, varbytes(ss));
        offset += varbytes(ss);
        std::memcpy(&rs,  span.data() + offset, varbytes(rs));
        offset += varbytes(rs);
        std::memcpy(&pcl, span.data() + offset, varbytes(pcl));
        offset += varbytes(pcl);
        std::memcpy(&sc,  span.data() + offset, varbytes(sc));
        offset += varbytes(sc);
        
        if (sc == 0 || sc > GCRYPT_SESSION_MAX_KEY_SKIP)
            return convert_error<bytespan, messaging_session>("Invalid skipped key count found in deserialization: " + sc);
        size_t left = span.size() - offset;
        // we want a strict size match.
        if (left != sc * typebytes(skipped_message_key))
            return convert_error<bytespan, messaging_session>("Remaining bytes for skipped message keys was not equal to specified smk count.");
        smks.reserve(sc);
        
        for(size_t i = 0; i < sc; i++)
        {
            auto mem = span.subspan(offset + i * typebytes(skipped_message_key), typebytes(skipped_message_key));
            auto result = skipped_message_key::from_bytes(mem);

            if (!result.has_value())
                return std::unexpected(result.error());
            smks.push_back(*result);
        }
        messaging_session session = make_empty(recipientId);
        
        session.rstate.remoteIdentityKey = rik,
        session.rstate.rootKey = rk,
        session.rstate.sendingChainKey = sck,
        session.rstate.receivingChainKey = rck,
        session.rstate.localRatchetKey = lrk,
        session.rstate.remoteRatchetKey = rrk,
        session.sendSequence = ss,
        session.receiveSequence = rs,
        session.previousChainLength = pcl,
        session.skippedKeys = std::move(smks);

        return session;
    }
    /// @brief Serializes the messaging session in the order of which the keys are defined in the structure.
    ///        Followed by all sequence counters. Then comes the skipped keys, which we first write a size_t
    ///        For the length of the skipped keys, then each key sequentially.
    /// @return the resulting bytes.
    bytedata messaging_session::to_bytes() const
    {
        bytedata data;
        data.resize(typebytes(messaging_session));

        size_t off = util::write_key_bytes(data, 0,
                                rstate.remoteIdentityKey,
                                rstate.rootKey,
                                rstate.sendingChainKey,
                                rstate.receivingChainKey,
                                rstate.localRatchetKey.Public,
                                rstate.localRatchetKey.Private,
                                rstate.remoteRatchetKey);
        std::ranges::copy(util::bytes(sendSequence),        data.begin() + off);
        std::ranges::copy(util::bytes(receiveSequence),     data.begin() + (off += varbytes(sendSequence)));
        std::ranges::copy(util::bytes(previousChainLength), data.begin() + (off += varbytes(receiveSequence)));
        std::ranges::copy(util::bytes(static_cast<uint32_t>(skippedKeys.size())), data.begin() + (off += varbytes(previousChainLength)));
        
        constexpr auto converter = [](const skipped_message_key& it)
        { return it.to_bytes(); };
        
        auto skipped = skippedKeys |
            std::views::transform(converter) | std::views::join;
        data.append_range(skipped);
        
        return data;
    }
    bytedata messaging_session::header()
    {
        bytedata data(GCRYPT_HEADER_LEN);

        util::kcpy(rstate.localRatchetKey.Public, bytespan(data));
        std::memcpy(data.data() + typebytes(xckey),
                    static_cast<void*>(&sendSequence),
                    varbytes(sendSequence));
        std::memcpy(data.data() + typebytes(xckey) + varbytes(sendSequence),
                    static_cast<void*>(&previousChainLength),
                    varbytes(previousChainLength));
        
        return data;
    }
    message_header messaging_session::get_header(const bytespan& data)
    {
        // TODO: Encryption / Decryption
        message_header header{};

        util::load_keyb(data, header.ratchet);
        header.cmn = *reinterpret_cast<uint32_t*>(data.data() + varbytes(header.ratchet));
        header.cpn = *reinterpret_cast<uint32_t*>(data.data() + varbytes(header.ratchet) + typebytes(uint32_t));

        return header;
    }

    std::tuple<key<32>, uint32_t> messaging_session::ratchet_send_key()
    {
        constexpr size_t LHS = varbytes(rstate.sendingChainKey), RHS = varbytes(skipped_message_key::messageKey);

        key<32> mk;
        std::tie(rstate.sendingChainKey, mk) = util::kcut<LHS, RHS>(HKDF::KDF<(LHS + RHS)>(rstate.sendingChainKey));

        return std::make_tuple(mk, sendSequence++);
    }
    void messaging_session::commit_state()
    {
        skippedKeys.append_range(rstate.stagedSkippedKeys);
        rstate.stagedSkippedKeys.clear();
        
        bytedata bytes = to_bytes();

        GCRYPT_ISTORE->store_session(identifier, bytes);
    }
    ratchet_result messaging_session::ratchet_encrypt(const bytespan& msg)
    {
        GCRYPT_ASSERT_STORE();
        auto lid = GCRYPT_ISTORE->load_identity_key_pair();

        if (!lid.has_value())
            return ratchet_failed(RatchetFailureType::STORAGE_FAILED, "Could not encrypt data. IStore failed to fetch local keys.");

        ratchet_state cstate = state();

        // NOTE: try block might not be necessary. This is not great for performance.
        try
        {
            // only keep public key.
            xckey lid_p;
            std::copy(lid->begin(), lid->begin() + typebytes(xckey), lid_p.begin());

            constexpr std::string_view ver_str = GCRYPT_VERSION_STRING;
            static key<ver_str.size()> ver;
            std::memcpy(ver.data(), ver_str.data(), ver_str.size());

            bytedata head = header();

            auto AD = util::kconcat(ver, lid_p, rstate.remoteIdentityKey);

            const auto& [mk, sseq] = ratchet_send_key();

            auto ct = AEAD::encrypt(msg, AD, mk);

            head.insert(head.end(), ct.begin(), ct.end());
            
            commit_state();
            return head;
        }catch(std::exception& e)
        {
            rollback_state(cstate);
            return ratchet_failed(RatchetFailureType::BAD_ENCRYPT, e.what());
        }
    }
    ratchet_step_result<key<32>> messaging_session::ratchet_receive_key(const message_header& header)
    {
        auto mkey = try_skipped_msg_keys(header);
        
        if (mkey)
            return *mkey;

        if (!util::kmatch(header.ratchet, rstate.remoteRatchetKey))
        {
            auto failed = skip_msg_keys(header.cpn);
            if (failed)
                return std::unexpected(*failed);

            dh_ratchet(header);
        }
        auto failed = skip_msg_keys(header.cmn);
        if (failed)
            return std::unexpected(*failed);

        constexpr size_t LHS = varbytes(rstate.receivingChainKey), RHS = varbytes(skipped_message_key::messageKey);

        key<32> mk;
        std::tie(rstate.receivingChainKey, mk) = util::kcut<LHS, RHS>(HKDF::KDF<(LHS + RHS)>(rstate.receivingChainKey));
        receiveSequence++;
        return mk;
    }

    ratchet_result messaging_session::ratchet_decrypt(const bytespan& data)
    {
        GCRYPT_ASSERT_STORE();

        auto lid = GCRYPT_ISTORE->load_identity_key_pair();

        if (!lid.has_value())
            return ratchet_failed(RatchetFailureType::STORAGE_FAILED, "Could not decrypt data. IStore failed to fetch local keys.");

        ratchet_state cstate = state();

        try
        {
            // only keep public key.
            xckey lid_p;
            std::copy(lid->begin(), lid->begin() + typebytes(xckey), lid_p.begin());

            constexpr std::string_view ver_str = GCRYPT_VERSION_STRING;
            static key<ver_str.size()> ver;
            std::memcpy(ver.data(), ver_str.data(), ver_str.size());

            auto AD = util::kconcat(ver, rstate.remoteIdentityKey, lid_p);

            if (data.size() < typebytes(message_header))
                return ratchet_failed(RatchetFailureType::MALFORMED_INPUT, "Insufficient bytes in byte array to cover header size.");
            
            auto header = get_header(data);
            auto mk     = ratchet_receive_key(header);

            if (!mk)
            {
                rollback_state(cstate);
                return ratchet_failed(RatchetFailureType::BAD_DECRYPT, "Ratchet step could not receive key from header.");
            }
            bytespan ciphertext = data.subspan(GCRYPT_HEADER_LEN);

            auto d = AEAD::decrypt(ciphertext, AD, *mk);
            if (!d)
            {
                rollback_state(cstate);
                return ratchet_failed(RatchetFailureType::BAD_DECRYPT, "AEAD Protocol failed decrypt.");
            }

            commit_state();
            return *d;
        }catch(std::exception& e)
        {
            rollback_state(cstate);
            return ratchet_failed(RatchetFailureType::BAD_DECRYPT, e.what());
        }
    }

    std::optional<xckey> messaging_session::try_skipped_msg_keys(const message_header& header)
    {
        // uses linear search
        // TODO: map impl for faster searching (need key concat of message num for hash support)
        auto it = std::find_if(skippedKeys.begin(), skippedKeys.end(), [&header](const skipped_message_key& val)
        {
            return val.sequenceNumber == header.cmn && util::kmatch(header.ratchet, val.ratchetPublicKey);
        });

        if (it == skippedKeys.end())
            return std::nullopt;

        xckey messageKey = util::kcpy(it->messageKey);
        skippedKeys.erase(it);
        return messageKey;
    }
    std::optional<RatchetStepError> messaging_session::skip_msg_keys(int until)
    {
        // TODO
        if (receiveSequence + GCRYPT_SESSION_MAX_KEY_SKIP < until)
            return RatchetStepError(RatchetFailureType::MAX_SKIP_REACHED, "Max skip reached.");
        if (rstate.receivingChainKey.data() != nullptr)
            while (receiveSequence < until)
            {
                constexpr size_t LHS = varbytes(rstate.receivingChainKey), RHS = varbytes(skipped_message_key::messageKey);
                const auto kdfout = HKDF::KDF<(LHS + RHS)>(rstate.receivingChainKey);
                
                skipped_message_key skipped
                {
                    .ratchetPublicKey = rstate.remoteRatchetKey,
                    .sequenceNumber = receiveSequence
                };

                std::tie(rstate.receivingChainKey, skipped.messageKey) = util::kcut<LHS, RHS>(kdfout);

                skippedKeys.push_back(std::move(skipped));
                receiveSequence++;
            }
        return std::nullopt;
    }
    // subfunction of dh_ratchet, moved to allow constructor to call this functionality.
    ratchet_step_status messaging_session::dhstep()
    {
        auto newDH = keygen::X25519::make_pair();
        
        if (!newDH)
            throw newDH.error();

        // perform ratchet step again
        rstate.localRatchetKey = newDH.value();
        xckey dhOut = X25519::ssecret(rstate.localRatchetKey.Private, rstate.remoteRatchetKey);

        // generate keys for next sending
        // now assign to sendingchainkey
        std::tie(rstate.rootKey, rstate.sendingChainKey) = HKDF::KDF_rk(rstate.rootKey, dhOut);
        return std::nullopt;
    }
    ratchet_step_status messaging_session::dh_ratchet(const message_header& header)
    {
        previousChainLength = sendSequence;
        sendSequence = 0;
        receiveSequence = 0;

        rstate.remoteRatchetKey = header.ratchet;

        xckey dhOut = X25519::ssecret(rstate.localRatchetKey.Private, rstate.remoteRatchetKey);

        std::tie(rstate.rootKey, rstate.receivingChainKey) = HKDF::KDF_rk(rstate.rootKey, dhOut);

        return dhstep();
    }

}