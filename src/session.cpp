#include "session.hpp"
#include "util.hpp"
#include "store.hpp"
#include "algorithms.hpp"
#include <algorithm>

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