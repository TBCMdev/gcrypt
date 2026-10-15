#include "session.hpp"
#include "util.hpp"
#include "store.hpp"
#include "algorithms.hpp"
#include <algorithm>
#include <ranges>

namespace gcrypt::session
{

    messaging_session::messaging_session(const xckey& SK, const xckey& PeerDHPublicKey, const key<32>& masterSecretKey) :
        remoteIdentityKey(SK),
        remoteRatchetKey(PeerDHPublicKey),
        rootKey(masterSecretKey)
    {
        dhstep();
    }
    messaging_session::messaging_session(const xckey& SK, const xckeypair& LRK, const key<32>& masterSecretKey) :
        remoteIdentityKey(SK),
        localRatchetKey(LRK),
        rootKey(masterSecretKey)
    {
        // master secret already derived and received.
    }
    util::convert_result<skipped_message_key> skipped_message_key::from_bytes(const fixed_bytespan& from)
    {
        if (from.size() < bytesize<skipped_message_key>())
            return convert_error<fixed_bytespan, skipped_message_key>("Bytearray not long enough for sizeof(skipped_message_key)");
        size_t offset = 0;

        xckey rpk;
        key<32> mk;
        uint32_t sn;

        const std::span<const uint8_t> span(from.begin(), from.end());

        util::load_keyb(span, rpk, offset);
        util::load_keyb(span, mk,  offset += sizeof(rpk));
        std::memcpy(&sn,  span.data() + offset, sizeof(sn));

        return skipped_message_key{rpk, mk, sn};
    }

    bytedata skipped_message_key::to_bytes() const
    {
        bytedata data;
        data.reserve(bytesize<skipped_message_key>());

        size_t off = util::write_key_bytes(data, 0, ratchetPublicKey, messageKey);
        
        std::ranges::copy(util::bytes(sequenceNumber), data.begin() + off);

        return data;
    }
    util::convert_result<messaging_session> messaging_session::from_bytes(const fixed_bytespan& from)
    {
        if (from.size() < bytesize<messaging_session>())
            return convert_error<fixed_bytespan, messaging_session>("Bytearray not long enough for sizeof(messaging_session).");

        size_t offset = 0;

        xckey rik;
        key<32> rk, sck, rck;
        xckeypair lrk;
        xckey rrk;
        uint32_t ss, rs, pcl;
        size_t sc; // skipped count
        std::vector<skipped_message_key> smks;

        const std::span<const uint8_t> span(from.begin(), from.end());

        // for security, we should use load_keyb_s (load key bytes safe) to zero the memory after loading from the span.
        // however the current parent implementation expects a const span, so we cannot modify the data.
        util::load_keyb(span, rik,         offset);
        util::load_keyb(span, rk,          offset += sizeof(rik));
        util::load_keyb(span, sck,         offset += sizeof(rk));
        util::load_keyb(span, rck,         offset += sizeof(sck));
        util::load_keyb(span, lrk.Public,  offset += sizeof(rck));
        util::load_keyb(span, lrk.Private, offset += sizeof(lrk.Public));
        util::load_keyb(span, rrk,         offset += sizeof(lrk.Private));
        
        offset += sizeof(lrk.Private);

        std::memcpy(&ss,  span.data() + offset, sizeof(ss));
        offset += sizeof(ss);
        std::memcpy(&rs,  span.data() + offset, sizeof(rs));
        offset += sizeof(rs);
        std::memcpy(&pcl, span.data() + offset, sizeof(pcl));
        offset += sizeof(pcl);
        std::memcpy(&sc,  span.data() + offset, sizeof(sc));
        offset += sizeof(sc);
        
        if (sc == 0 || sc > GCRYPT_SESSION_MAX_KEY_SKIP)
            return convert_error<bytespan, messaging_session>("Invalid skipped key count found in deserialization: " + sc);
        size_t left = span.size() - offset;
        // we want a strict size match.
        if (left != sc * sizeof(skipped_message_key))
            return convert_error<bytespan, messaging_session>("Remaining bytes for skipped message keys was not equal to specified smk count.");
        smks.reserve(sc);
        
        for(size_t i = 0; i < left; i++)
        {
            auto mem = span.subspan(offset, i * sizeof(skipped_message_key));
            auto result = skipped_message_key::from_bytes(mem);

            if (!result.has_value())
                return std::unexpected(result.error());
            smks.push_back(*result);
        }
        messaging_session session = make_empty();
        
        session.remoteIdentityKey = rik,
        session.rootKey = rk,
        session.sendingChainKey = sck,
        session.receivingChainKey = rck,
        session.localRatchetKey = lrk,
        session.remoteRatchetKey = rrk,
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
        data.resize(bytesize<messaging_session>());

        size_t off = util::write_key_bytes(data, 0,
                                remoteIdentityKey,
                                rootKey,
                                sendingChainKey,
                                receivingChainKey,
                                localRatchetKey.Public,
                                localRatchetKey.Private,
                                remoteRatchetKey);
        std::ranges::copy(util::bytes(sendSequence),        data.begin() + off);
        std::ranges::copy(util::bytes(receiveSequence),     data.begin() + (off += sizeof(sendSequence)));
        std::ranges::copy(util::bytes(previousChainLength), data.begin() + (off += sizeof(receiveSequence)));
        std::ranges::copy(util::bytes(skippedKeys.size()), data.begin() + (off += sizeof(previousChainLength)));
        
        
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

        util::kcpy(remoteRatchetKey, bytespan(data));
        std::memcpy(data.data() + sizeof(xckey),
                    static_cast<void*>(&sendSequence),
                    sizeof(sendSequence));
        std::memcpy(data.data() + sizeof(xckey) + sizeof(sendSequence),
                    static_cast<void*>(&previousChainLength),
                    sizeof(previousChainLength));
        
        return data;
    }
    message_header messaging_session::get_header(const bytespan& data)
    {
        // TODO: Encryption / Decryption
        message_header header{};

        util::load_keyb(data, header.ratchet);
        header.cmn = *reinterpret_cast<uint32_t*>(data.data() + sizeof(header.ratchet));
        header.cpn = *reinterpret_cast<uint32_t*>(data.data() + sizeof(header.ratchet) + sizeof(uint32_t));

        return header;
    }

    std::tuple<key<32>, uint32_t> messaging_session::ratchet_send_key()
    {
        constexpr size_t LHS = sizeof(sendingChainKey), RHS = sizeof(skipped_message_key::messageKey);

        key<32> mk;
        std::tie(sendingChainKey, mk) = util::kcut<LHS, RHS>(HKDF::KDF<(LHS + RHS)>(sendingChainKey));

        return std::make_tuple(mk, sendSequence++);
    }
    bytedata messaging_session::ratchet_encrypt(const bytespan& msg)
    {
        GCRYPT_ASSERT_STORE();
        auto lid = GCRYPT_ISTORE->load_identity_key_pair();

        if (!lid.has_value())
            throw std::runtime_error("Could not encrypt data. IStore failed to fetch local keys.");

        // only keep public key.
        xckey lid_p;
        std::copy(lid->begin(), lid->begin() + sizeof(xckey), lid_p.begin());

        constexpr std::string_view ver_str = GCRYPT_VERSION_STRING;
        static key<ver_str.size()> ver;
        std::memcpy(ver.data(), ver_str.data(), ver_str.size());

        bytedata head = header();

        auto AD = util::kconcat(ver, lid_p, remoteIdentityKey);

        const auto& [mk, sseq] = ratchet_send_key();

        auto ct = AEAD::encrypt(msg, AD, mk);

        head.insert(head.end(), ct.begin(), ct.end());
        return head;
    }
    key<32> messaging_session::ratchet_receive_key(const message_header& header)
    {
        auto mkey = try_skipped_msg_keys(header);
        
        if (mkey)
            return *mkey;

        if (!util::kmatch(header.ratchet, remoteRatchetKey))
        {
            skip_msg_keys(header.cpn);
            dh_ratchet(header);
        }
        skip_msg_keys(header.cmn);

        constexpr size_t LHS = sizeof(receivingChainKey), RHS = sizeof(skipped_message_key::messageKey);

        key<32> mk;
        std::tie(receivingChainKey, mk) = util::kcut<LHS, RHS>(HKDF::KDF<(LHS + RHS)>(receivingChainKey));
        receiveSequence++;
        return mk;
    }

    std::optional<bytedata> messaging_session::ratchet_decrypt(const bytespan& data)
    {
        GCRYPT_ASSERT_STORE();

        auto lid = GCRYPT_ISTORE->load_identity_key_pair();

        if (!lid.has_value())
            throw std::runtime_error("Could not decrypt data. IStore failed to fetch local keys.");

        // only keep public key.
        xckey lid_p;
        std::copy(lid->begin(), lid->begin() + sizeof(xckey), lid_p.begin());

        constexpr std::string_view ver_str = GCRYPT_VERSION_STRING;
        static key<ver_str.size()> ver;
        std::memcpy(ver.data(), ver_str.data(), ver_str.size());

        auto AD = util::kconcat(ver, lid_p, remoteIdentityKey);

        auto header = get_header(data);

        auto mk = ratchet_receive_key(header);

        bytespan ciphertext = data.subspan(GCRYPT_HEADER_LEN);

        return AEAD::decrypt(ciphertext, AD, mk);
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
    void messaging_session::skip_msg_keys(int until)
    {
        // TODO
        if (receiveSequence + GCRYPT_SESSION_MAX_KEY_SKIP < until)
            throw std::runtime_error("Max skip reached.");
        if (receivingChainKey.data() != nullptr)
            while (receiveSequence < until)
            {
                constexpr size_t LHS = sizeof(receivingChainKey), RHS = sizeof(skipped_message_key::messageKey);
                const auto kdfout = HKDF::KDF<(LHS + RHS)>(receivingChainKey);
                
                skipped_message_key skipped
                {
                    .ratchetPublicKey = remoteRatchetKey,
                    .sequenceNumber = receiveSequence
                };

                std::tie(receivingChainKey, skipped.messageKey) = util::kcut<LHS, RHS>(kdfout);

                skippedKeys.push_back(std::move(skipped));
                receiveSequence++;
            }
    }
    // subfunction of dh_ratchet, moved to allow constructor to call this functionality.
    void messaging_session::dhstep()
    {
        auto newDH = keygen::X25519::make_pair();
        
        if (!newDH)
            throw newDH.error();

        // perform ratchet step again
        localRatchetKey = newDH.value();
        xckey dhOut = X25519::ssecret(localRatchetKey.Private, remoteRatchetKey);

        // generate keys for next sending
        // now assign to sendingchainkey
        std::tie(rootKey, sendingChainKey) = HKDF::KDF_rk(rootKey, dhOut);
    }
    void messaging_session::dh_ratchet(const message_header& header)
    {
        previousChainLength = sendSequence;
        sendSequence = 0;
        receiveSequence = 0;

        remoteRatchetKey = header.ratchet;

        xckey dhOut = X25519::ssecret(localRatchetKey.Private, remoteRatchetKey);

        std::tie(rootKey, receivingChainKey) = HKDF::KDF_rk(rootKey, dhOut);

        dhstep();

    }

}