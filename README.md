### Install PBC Library
```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar zxvf pbc-0.5.14.tar.gz
cd pbc
./configure
make
sudo make install
sudo ldconfig
```

### Build Blake3
```bash
git clone https://github.com/BLAKE3-team/BLAKE3.git
cd BLAKE3/c
gcc -c -fPIC -O3 -msse2 blake3_sse2.c -o blake3_sse2.o
gcc -c -fPIC -O3 -msse4.1 blake3_sse41.c -o blake3_sse41.o
gcc -c -fPIC -O3 -mavx2 blake3_avx2.c -o blake3_avx2.o
gcc -c -fPIC -O3 -mavx512f -mavx512vl blake3_avx512.c -o blake3_avx512.o
gcc -shared -O3 -o libblake3.so blake3.c blake3_dispatch.c blake3_portable.c \
    blake3_avx2.o blake3_avx512.o blake3_sse41.o blake3_sse2.o
sudo cp libblake3.so /lib/x86_64-linux-gnu/
```

### Build
```bash
cd wildcarded-sm9
mkdir build && cd build
cmake ..
make
```