SETLOCAL EnableDelayedExpansion
SET "OPENSSL_DIR=C:\openssl102"
SET "LIBCURL_DIR=C:\Users\mam0nt\curl"
SET "CUDA_COMPUTE_ARCHS=86 90"
SET "CUDA_PTX_FALLBACK=52"
SET "BLOCK_DIM=64"
SET "WORKSPACE=0x400000"

SET "GENCODE_ARGS="
FOR %%A IN (%CUDA_COMPUTE_ARCHS%) DO (
    SET "GENCODE_ARGS=!GENCODE_ARGS! -gencode arch=compute_%%A,code=sm_%%A"
)
IF NOT "!CUDA_PTX_FALLBACK!"=="" (
    SET "GENCODE_ARGS=!GENCODE_ARGS! -gencode arch=compute_!CUDA_PTX_FALLBACK!,code=compute_!CUDA_PTX_FALLBACK!"
)

cd src
nvcc -o ../miner.exe -Xcompiler "/std:c++14" !GENCODE_ARGS! -DBLOCK_DIM=%BLOCK_DIM% -DNONCES_PER_ITER=%WORKSPACE%^
 -I %OPENSSL_DIR%\include ^
 -I %LIBCURL_DIR%\include ^
 -l %LIBCURL_DIR%\builds\libcurl-vc-x64-release-dll-ipv6-sspi-winssl-obj-lib/libcurl ^
 -l %OPENSSL_DIR%\lib\libeay32 -L %OPENSSL_DIR%/lib ^
 -lnvml ^
conversion.cc cryptography.cc definitions.cc jsmn.c httpapi.cc ^
mining.cu prehash.cu processing.cc request.cc easylogging++.cc bip39/bip39.cc bip39/util.cc autolykos.cu

nvcc -o ../test.exe -Xcompiler "/std:c++14" !GENCODE_ARGS! -DBLOCK_DIM=%BLOCK_DIM% -DNONCES_PER_ITER=%WORKSPACE%^
 -I %OPENSSL_DIR%\include ^
 -I %LIBCURL_DIR%\include ^
 -l %LIBCURL_DIR%\builds\libcurl-vc-x64-release-dll-ipv6-sspi-winssl-obj-lib/libcurl ^
 -l %OPENSSL_DIR%\lib\libeay32 -L %OPENSSL_DIR%/lib ^
test.cu conversion.cc cryptography.cc definitions.cc jsmn.c ^
mining.cu prehash.cu processing.cc request.cc easylogging++.cc
cd ..
SET PATH=%PATH%;C:\Program Files\NVIDIA Corporation\NVSMI
ENDLOCAL
