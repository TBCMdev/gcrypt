#include "store.hpp"

namespace gcrypt::store
{
    void Init(storage_manager* managerInstance)
    {
        GCRYPT_ISTORE = std::shared_ptr<storage_manager>(managerInstance);
    }
}