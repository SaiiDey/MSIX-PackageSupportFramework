@echo off
echo "==================== PSF x86  DEBUG  ================================="
rem msbuild CentennialFixups.sln /p:platform=x86;configuration=debug
echo "==================== PSF x86 RELEASE ================================="
rem msbuild CentennialFixups.sln /p:platform=x86;configuration=release
echo "==================== PSF x64  DEBUG  ================================="
msbuild CentennialFixups.sln /p:platform=x64;configuration=debug
echo "==================== PSF x64 RELEASE ================================="
rem msbuild CentennialFixups.sln /p:platform=x64;configuration=release
pushd tests
echo "==================== TEST x86  DEBUG  ================================="
rem msbuild tests.sln /p:platform=x86;configuration=debug
echo "==================== TEST x86 RELEASE ================================="
rem msbuild tests.sln /p:platform=x86;configuration=release
echo "==================== TEST x64  DEBUG  ================================="
rem msbuild tests.sln /p:platform=x64;configuration=debug
echo "==================== TEST x64 RELEASE ================================="
rem msbuild tests.sln /p:platform=x64;configuration=release
popd
