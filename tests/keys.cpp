#include "gcrypt.hpp"
#include <iostream>

using namespace gcrypt;



bool testSignatures()
{
    auto alice_keys = pqxdh::make_lkb(0), bob_keys = pqxdh::make_lkb(1);

    constexpr uint32_t pks = 1;
    auto alice_payload = pqxdh::make_server_payload<pks>(0, alice_keys);
    auto bob_payload   = pqxdh::make_server_payload<pks>(1, bob_keys);
    
    constexpr auto bobID = "bob", aliceID = "alice";

    auto alice_fpkb_bob = pqxdh::foreign_prekey_bundle
    {
        .identityKey = bob_payload.identityKey,
        .signedPreKey = bob_payload.signedPreKey,
        .qpubsidkey = bob_payload.signedOneTimeQuantumPreKeys[0],
        .oneTimePreKey = bob_payload.oneTimePreKeys[0],
    };
    return pqxdh::verify_foreign_bundle(bob_payload.identityKey, alice_fpkb_bob);
}

int main()
{
    std::cout << "Testing signatures...\n";
    if (testSignatures())
        std::cout << "Signatures test passed.\n";
    else
        std::cout << "Signature test failed.\n";
    
    return EXIT_SUCCESS;
}