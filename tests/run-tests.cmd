@echo off
setlocal
pushd "%~dp0.."
if not exist test-output mkdir test-output
cl /nologo /std:c++17 /EHsc /MD tests\response_headers_test.cpp /Fo:test-output\headers.obj /Fe:test-output\headers.exe
if errorlevel 1 exit /b 1
test-output\headers.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /MT /Ilibsodium tests\payload_verifier_test.cpp /Fo:test-output\payload.obj /Fe:test-output\payload.exe /link libsodium\libsodium.lib
if errorlevel 1 exit /b 1
test-output\payload.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /MD tests\file_digest_test.cpp /Fo:test-output\digest.obj /Fe:test-output\digest.exe
if errorlevel 1 exit /b 1
test-output\digest.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /MD /I. tests\json_errors_test.cpp /Fo:test-output\json.obj /Fe:test-output\json.exe
if errorlevel 1 exit /b 1
test-output\json.exe
if errorlevel 1 exit /b 1
if not exist x64\Release\library_x64.lib exit /b 1
cl /nologo /std:c++17 /EHsc /MD /DSODIUM_STATIC /I. /Ilibsodium tests\api_lifecycle_test.cpp /Fo:test-output\lifecycle.obj /Fe:test-output\lifecycle.exe /link x64\Release\library_x64.lib curl\zlib.lib user32.lib shell32.lib
if errorlevel 1 exit /b 1
test-output\lifecycle.exe
if errorlevel 1 exit /b 1
popd
