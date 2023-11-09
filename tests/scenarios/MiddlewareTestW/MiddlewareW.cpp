//-------------------------------------------------------------------------------------------------------
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//-------------------------------------------------------------------------------------------------------

#include <test_config.h>
#include <appmodel.h>
#include <algorithm>
#include <ShlObj.h>
#include <filesystem>
#include <dependency_helper.h>

using namespace std::literals;

#define Valid_dependency_key_name_1      L"Software\\notepad"
#define Valid_dependency_key_name_2(v)   L"Software\\apps\\notepad\\" v "\\path"
#define Valid_dependency_version         L"Version"
#define Valid_dependency_install_path    L"InstalledPath"
#define Valid_dependency_install_version L"InstalledVersion"

#define Invalid_dependency_key_name_1      L"Software\\NonExistant"
#define Invalid_dependency_key_name_2(v)   L"Software\\newkey\\" v


#define FULL_RIGHTS_ACCESS_REQUEST   KEY_ALL_ACCESS
#define RW_ACCESS_REQUEST            KEY_READ | KEY_WRITE


int wmain(int argc, const wchar_t** argv)
{
    auto result = parse_args(argc, argv);
    test_initialize("MiddlewareW Tests", 1);

    auto opt_pkg = query_package_with_name(MicrosoftNotepadPackageFamily);
    if (opt_pkg.has_value())
    {
        test_begin("RegLegacy Test ModifyKeyAccess HKCU");
        try
        {
            HKEY HKCU_Verify;
            if (RegOpenKeyW(HKEY_CURRENT_USER, Valid_dependency_key_name_1, &HKCU_Verify) == ERROR_SUCCESS)
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
    }
    else
    {
		trace_message("Notepad is not installed on the system", console::color::yellow, true);
        result = 1;
	}
    return result;
}
