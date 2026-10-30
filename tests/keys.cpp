#include "gcrypt.hpp"
#include <iostream>

using namespace gcrypt;

#define assert(b, ...) if (!(b)) {std::cout << "Failed: " << __VA_ARGS__ << '\n'; exit(1);}


bool testSignatures()
{
    try{
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
    }catch(std::runtime_error& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }
}
xckey u_old_to_y(const xckey& U)
{
    // Constant 1
    const xckey C1 = keygen::from_lebytes<GCRYPT_X25519_KEY_SIZE>((uint8_t)1);

    xckey numerator{}; // Z = U - 1
    crypto_core_ed25519_scalar_sub(numerator.data(), U.data(), C1.data());
    xckey denominator{}; // Z = U - 1
    crypto_core_ed25519_scalar_add(denominator.data(), U.data(), C1.data());

    xckey r{};
    if (crypto_core_ed25519_scalar_invert(r.data(), denominator.data()) != 0)
        throw std::invalid_argument("Invalid scalar of ed25519 denominator (=0)");
    
    xckey result{};
    crypto_core_ed25519_scalar_mul(result.data(), numerator.data(), r.data());

    return result;
}
xckey convert_mont_old(const xckey& U)
{
    xckey umasked = Ed25519::ycoord(U);
    xckey P = u_old_to_y(umasked);

    Ed25519::ycoord(&P);

    return P;
}

void testConvertMont()
{
    xckey u9{}, u92{};
    // std::memset(u9.data(), 0x00, typebytes(xckey));
    u9[0] = 9;
    u92[0] = 9;
    
    std::cout << "Input:      " << u9.str() << '\n';
    std::cout << "Old Input:  " << u92.str() << '\n';
    xckey y = gcrypt::XedDSA::impl::convert_mont(u9);
    xckey y2 = convert_mont_old(u92);
    // expected (little-endian): 58 66 66 66 ... 66
    std::cout << "Output:     " << y.str() << '\n';
    std::cout << "Old Output: " << y2.str() << '\n';
    assert(y[0] == 0x58, "not 0x58");
    for (int i = 1; i < 32; i++) assert(y[i] == 0x66, "not 0x66");
    assert(crypto_core_ed25519_is_valid_point(y.data()) == 1, "not valid.");
}

int main()
{
    int e;
    if ((e = gcrypt::init()) != 0)
    {
        std::cout << "Could not initialize gcrypt library. exit:" << e << std::endl;
        return e;
    }

    std::cout << "Testing signatures...\n";
    if (testSignatures())
        std::cout << "Signatures test passed.\n";
    else
        std::cout << "Signature test failed.\n";
    testConvertMont();
    
    return EXIT_SUCCESS;
}