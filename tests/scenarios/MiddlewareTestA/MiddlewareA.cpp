//-------------------------------------------------------------------------------------------------------
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//-------------------------------------------------------------------------------------------------------

#include <test_config.h>
#include <appmodel.h>
#include <algorithm>
#include <ShlObj.h>
#include <filesystem>

using namespace std::literals;


#define Valid_dependency_key_name_1      "Software\\notepad"
#define Valid_dependency_key_name_2(v)   "Software\\apps\\notepad\\" v "\\path"
#define Valid_dependency_version         "Version"
#define Valid_dependency_install_path    "InstalledPath"
#define Valid_dependency_install_version "InstalledVersion"

#define Invalid_dependency_key_name_1      "Software\\NonExistant"
#define Invalid_dependency_key_name_2(v)   "Software\\newkey\\" v


#define FULL_RIGHTS_ACCESS_REQUEST   KEY_ALL_ACCESS
#define RW_ACCESS_REQUEST            KEY_READ | KEY_WRITE


int main(int argc, const char** argv)
{
    auto result = parse_args(argc, argv);
    test_initialize("MiddlewareA Tests", 3);

    test_begin("MiddlewareA Test ModifyKeyAccess HKCU");
    try
    {
        HKEY HKCU_Verify;
        if (RegOpenKeyA(HKEY_CURRENT_USER, Valid_dependency_key_name_1, &HKCU_Verify) == ERROR_SUCCESS)
        {
            RegCloseKey(HKCU_Verify);
        }
    }
    catch (...)
    {
        trace_message("Unexpected error.", console::color::red, true);
        result = GetLastError();
        print_last_error("Failed to MOdify HKCU RW Access case");
    }

    test_end(result);



    test_cleanup();
    Sleep(1000);
    return result;
}
