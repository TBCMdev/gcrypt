# Compiling

I use the following g++ command (not cmake) to compile my tests:

```bash
g++ -Idependencies/libsodium/include -Ldependencies/libsodium/lib/libsodium.a -I../build/_deps/mlkem_native-src/mlkem -I../src keys.cpp ../src/*.cpp -o testbin -std=c++23
```