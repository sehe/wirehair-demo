## Building

```bash
git clone --recurse https://github.com/sehe/wirehair-demo
cd wirehair-demo
cmake .
cmake --build .
```

## Running

```bash
./wirehair-demo wirehair-demo.cpp
```
    
Verify the result with

```bash
md5sum assets/wirehair-demo.cpp wirehair-demo.cpp
```
    
A larger set of files:

```bash
./wirehair-demo wirehair-demo.cpp deps/wirehair/*.h
(cd assets && find -type f -exec md5sum {} \+) | md5sum -c
```
