#!/bin/bash

# 에러 발생 시 스크립트 중단
set -e

echo "========================================="
echo "JSScanner Test Build Script"
echo "========================================="

# CMake 캐시 정리
echo "[1/8] Cleaning CMake cache files..."
rm -rf CMakeCache.txt CMakeFiles/ cmake_install.cmake Makefile

# CMake 설정
echo "[2/8] Running CMake configuration..."
cmake -DTEST=ON .

# 빌드 (모든 코어 활용)
CPU_CORES=$(nproc)
echo "[3/8] Building JSScanner with $CPU_CORES cores..."
make -j$CPU_CORES

# 빌드 결과 확인
if [ ! -f "JSScanner" ]; then
    echo "Error: JSScanner executable not found!"
    exit 1
fi

# 목적지 디렉터리 생성
TARGET_DIR="../../../Build/LinuxRelease"
BIN_DIR="${TARGET_DIR}/bin"
echo "[4/8] Creating target directories..."
mkdir -p "$TARGET_DIR"
mkdir -p "$BIN_DIR"

# JSScanner 실행 파일 복사
echo "[5/8] Copying JSScanner to $TARGET_DIR..."
cp JSScanner "$TARGET_DIR/"

# 공유 라이브러리 복사 함수
copy_shared_lib() {
    local rel_base="$1"
    local EXTERNAL_LIB_DIR="../../../../../mon47-opensrc/opensrc"
    local src_dir
    local base_name
    local found=0

    src_dir="$(dirname "${rel_base}")"
    base_name="$(basename "${rel_base}")"

    shopt -s nullglob
    for candidate in "${EXTERNAL_LIB_DIR}/${src_dir}/${base_name}.so"* "${EXTERNAL_LIB_DIR}/${src_dir}/${base_name}-"*.so*; do
        if [ -f "${candidate}" ] || [ -L "${candidate}" ]; then
            cp -a "${candidate}" "${BIN_DIR}/"
            found=1
        fi
    done
    shopt -u nullglob

    if [ "${found}" -eq 0 ]; then
        local archive="${EXTERNAL_LIB_DIR}/${src_dir}/${base_name}.a"
        if [ -f "${archive}" ]; then
            cp -a "${archive}" "${BIN_DIR}/"
            found=1
        fi
    fi

    if [ "${found}" -eq 0 ]; then
        echo "Warning: Shared library not found for ${rel_base}"
    fi
}

echo "[6/8] Copying shared libraries to $BIN_DIR..."
SHARED_LIBS=(
    "libpqxx/lib/libpqxx"
    "libpq/lib/libpq"
    "libpq/lib/libpgtypes"
    "libpq/lib/libecpg"
    "libpq/lib/libecpg_compat"
    "curl/lib/libcurl"
    "openssl/lib/libssl"
    "openssl/lib/libcrypto"
    "ada-url/lib/libada"
    "c-ares/lib/libcares"
    "zlib/lib/libz"
    "libidn2/lib/libidn2"
    "libpsl/lib/libpsl"
    "libunistring/lib/libunistring"
    "icu/lib/libicudata"
    "icu/lib/libicui18n"
    "icu/lib/libicuio"
    "icu/lib/libicuuc"
    "quickjs-ng/lib/libqjs"
)

for lib in "${SHARED_LIBS[@]}"; do
    copy_shared_lib "${lib}"
done

# RPATH 설정 (patchelf 사용)
if command -v patchelf &> /dev/null; then
    echo "[7/8] Setting RPATH for JSScanner..."
    patchelf --set-rpath '$ORIGIN:$ORIGIN/bin' "$TARGET_DIR/JSScanner"
else
    echo "Warning: patchelf not found. RPATH not set."
    echo "Install patchelf: sudo apt-get install patchelf"
fi

# 심볼릭 링크 생성
echo "[8/8] Creating symbolic link..."
rm -f ./JSScanner_Run
ln -s "$TARGET_DIR/JSScanner" ./JSScanner_Run

# 빌드 후 정리
echo "Cleaning up build artifacts..."
rm -rf CMakeCache.txt CMakeFiles/ cmake_install.cmake Makefile JSScanner

echo "========================================="
echo "Build completed successfully!"
echo "JSScanner executable: $TARGET_DIR/JSScanner"
echo "Shared libraries: $BIN_DIR"
echo "Symbolic link: ./JSScanner_Run"
echo ""
echo "To run JSScanner:"
echo "  ./JSScanner_Run"
echo "========================================="
