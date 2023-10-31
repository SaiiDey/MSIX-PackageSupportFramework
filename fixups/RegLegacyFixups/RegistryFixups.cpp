// Copyright (C) Tim Mangan. All rights reserved
//-------------------------------------------------------------------------------------------------------
// Copyright (C) Tim Mangan. All rights reserved
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//-------------------------------------------------------------------------------------------------------

#include <psf_framework.h>

#include "FunctionImplementations.h"
#include "Framework.h"
#include "Reg_Remediation_Spec.h"
#include "Logging.h"
#include <regex>
#include "psf_tracelogging.h"
#include "pch.h"
#include "unordered_set"

using namespace winrt::Windows::Management::Deployment;
using namespace winrt::Windows::ApplicationModel;
using namespace winrt::Windows::Foundation::Collections;

DWORD g_RegIntceptInstance = 0;
std::unordered_set<std::string> g_redirected_paths;
std::vector<std::wstring> g_created_keys_ordered;

void CreateRegistryRedirectEntries()
{
    Log("RegLegacyFixups Create redirected registry values\n");
    g_regRedirectRemediationInitialized = true;

    Package pkg = Package::Current();
    IVectorView<Package> dependencies = pkg.Dependencies();

    std::wregex dependency_version_regex = std::wregex(L"%dependency_version%");
    std::wregex dependency_path_regex = std::wregex(L"%dependency_root_path%");

    for (const auto& entry : g_regRemediationSpecs)
    {
        for (const auto& record : entry.remediationRecords)
        {
            if (record.remeditaionType == Reg_Remediation_Type_Redirect)
            {
                const auto& redirected_entry = record.redirectedEntry;

                Package depedency = nullptr;

#ifdef _DEBUG
                Log("Filtering required dependency\n");
#endif
                for (auto&& dep : dependencies) {
                    std::wstring_view name = dep.Id().Name();
#ifdef _DEBUG
                    Log("Checking package dependency %.*LS\n", name.length(), name.data());
#endif

                    if (name.find(redirected_entry.dependency) != std::wstring::npos) {
#ifdef _DEBUG
                        Log("Found required dependency\n");
#endif
                        depedency = dep;
                        break;
                    }
                }
                if (depedency == nullptr) 
                {
                    Log("No package with name %LS found\n", redirected_entry.dependency.c_str());
                    continue;
                }

                std::wstring dependency_path(depedency.EffectivePath());
                auto version = depedency.Id().Version();
                std::wstring dependency_version = std::to_wstring(version.Major) + L"." + std::to_wstring(version.Minor) + L"." + std::to_wstring(version.Build) + L"." + std::to_wstring(version.Revision);
                Log("Dependency path: %LS, version: %LS\n", dependency_path.c_str(), dependency_version.c_str());

                for (const auto& reg_entry : redirected_entry.data)
                {
                    HKEY res;
                    std::wstring reg_path = std::regex_replace(reg_entry.path, dependency_version_regex, dependency_version);

                    LSTATUS st = ::RegCreateKeyExW(HKEY_CURRENT_USER, reg_path.c_str(), 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &res, NULL);
                    if (st != ERROR_SUCCESS)
                    {
                        Log("Create key %LS failed\n", reg_entry.path.c_str());
                        return;
                    }

                    g_redirected_paths.insert(narrow(reg_path));
                    g_created_keys_ordered.push_back(reg_path);

                    for (const auto& it : reg_entry.values)
                    {
                        std::wstring value_data = std::regex_replace(it.second, dependency_path_regex, dependency_path);
                        value_data = std::regex_replace(value_data, dependency_version_regex, dependency_version);

                        st = ::RegSetValueExW(res, it.first.c_str(), 0, REG_SZ, (LPBYTE)value_data.c_str(),
                            (DWORD)(value_data.size() + 1 /* for null termination char */) * sizeof(wchar_t));

                        if (st != ERROR_SUCCESS)
                        {
#ifdef _DEBUG
                            Log("set value %s failed\n", it.first.c_str());
#endif
                        }
                    }
                }
            }
        }
    }
}

void CleanupFixups()
{
    Log("RegLegacyFixups CleanupFixups()\n");

    // Deleted the created keys in reverse order
    std::vector<std::wstring>::reverse_iterator redirected_path = g_created_keys_ordered.rbegin();

    while (redirected_path != g_created_keys_ordered.rend())
    {
        LSTATUS st = ::RegDeleteTreeW(HKEY_CURRENT_USER, redirected_path->c_str());
        if (st != ERROR_SUCCESS)
        {
            Log("Delete key %LS failed\n", redirected_path->c_str());
        }
        redirected_path++;
    }
}

std::string ReplaceRegistrySyntax(std::string regPath)
{
    std::string returnPath = regPath;

    // string returned is for pattern matching purposes, to keep consistent for the patterns,
    // revert to strings that look like HKEY_....
    if (regPath._Starts_with("=\\REGISTRY\\USER"))
    {
        if (regPath.length() > 15)
        {
            size_t offsetAfterSid = regPath.find('\\', 16);
            if (offsetAfterSid != std::string::npos)
            {
                returnPath = InterpretStringA("HKEY_CURRENT_USER") + regPath.substr(offsetAfterSid);
            }
            else
            {
                returnPath = InterpretStringA("HKEY_CURRENT_USER") + regPath.substr(15);
            }
        }
        else
        {
            returnPath = InterpretStringA("HKEY_CURRENT_USER");
        }
    }
    else if (regPath._Starts_with("=\\REGISTRY\\MACHINE"))
    {
        if (regPath.length() > 18)
        {
            size_t offsetAfterSid = regPath.find('\\', 19);
            if (offsetAfterSid != std::string::npos)
            {
                returnPath = InterpretStringA("HKEY_CURRENT_USER") + regPath.substr(offsetAfterSid);
            }
            else
            {
                returnPath = InterpretStringA("HKEY_LOCAL_MACHINE") + regPath.substr(18);
            }
        }
        else
        {
            returnPath = InterpretStringA("HKEY_LOCAL_MACHINE");
        }
    }
    return returnPath;
}
REGSAM RegFixupSam(std::string keypath, REGSAM samDesired, DWORD RegLocalInstance)
{
    keypath = ReplaceRegistrySyntax(keypath);
    REGSAM samModified = samDesired;
    std::string keystring;


    Log("[%d] RegFixupSam: path=%s\n", RegLocalInstance, keypath.c_str());
    for (auto& spec : g_regRemediationSpecs)
    {
#ifdef _DEBUG
        Log("[%d] RegFixupSam: spec\n", RegLocalInstance);
#endif        
        for (auto& specitem: spec.remediationRecords)
        {
#ifdef _DEBUG
            Log("[%d] RegFixupSam: specitem.type=%d\n", RegLocalInstance, specitem.remeditaionType);
#endif   
            switch (specitem.remeditaionType)
            {
            case Reg_Remediation_Type_ModifyKeyAccess:
#ifdef _DEBUG
                Log("[%d] RegFixupSam: is Check ModifyKeyAccess...\n", RegLocalInstance);
#endif
                switch (specitem.modifyKeyAccess.hive)
                {
                case Modify_Key_Hive_Type_HKCU:
                    keystring = "HKEY_CURRENT_USER\\";
                    if (keypath._Starts_with(keystring))
                    {
#ifdef _DEBUG
                        Log("[%d] RegFixupSam: is HKCU key\n", RegLocalInstance);
#endif
                        for (auto& pattern : specitem.modifyKeyAccess.patterns)
                        {
#ifdef _DEBUG
                            Log("[%d] RegFixupSam: Check %LS\n", RegLocalInstance, widen(keypath.substr(keystring.size())).c_str());
                            Log("[%d] RegFixupSam: using %LS\n", RegLocalInstance, pattern.c_str());
#endif
                            try
                            {
                                if (std::regex_match(widen(keypath.substr(keystring.size())), std::wregex(pattern)))
                                {
#ifdef _DEBUG
                                    Log("[%d] RegFixupSam: is HKCU pattern match.\n", RegLocalInstance);
#endif
                                    switch (specitem.modifyKeyAccess.access)
                                    {
                                    case Modify_Key_Access_Type_Full2RW:
                                        if ((samDesired & (KEY_ALL_ACCESS | KEY_CREATE_LINK)) != 0)
                                        {
                                            samModified = samDesired & ~(DELETE | KEY_CREATE_LINK);
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: Full2RW\n", RegLocalInstance);
#endif
                                        }
                                        break;
                                    case Modify_Key_Access_Type_Full2MaxAllowed:
                                        if ((samDesired & (DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK)) != 0)
                                        {
                                            samModified = MAXIMUM_ALLOWED;
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: Full2MaxAllowed\n", RegLocalInstance);
#endif                                    
                                        }
                                    case Modify_Key_Access_Type_Full2R:
                                        if ((samDesired & (DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK)) != 0)
                                        {
                                            samModified = samDesired & ~(DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK);
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: Full2R\n", RegLocalInstance);
#endif
                                        }
                                    case Modify_Key_Access_Type_RW2R:
                                        if ((samDesired & (KEY_CREATE_LINK | KEY_CREATE_SUB_KEY | KEY_SET_VALUE)) != 0)
                                        {
                                            samModified = samDesired & ~(DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK);
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: RW2R\n", RegLocalInstance);
#endif
                                        }
                                    case Modify_Key_Access_Type_RW2MaxAllowed:
                                        if ((samDesired & (KEY_CREATE_LINK | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | WRITE_DAC | WRITE_OWNER)) != 0)
                                        {
                                            samModified = MAXIMUM_ALLOWED;
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: RW2MaxAllowed\n", RegLocalInstance);
#endif                                    
                                        }
                                    default:
                                        break;
                                    }
                                    return samModified;
                                }
                            }
                            catch (...)
                            {
                                psf::TraceLogExceptions("RegLegacyFixupException", "Bad Regex pattern ignored in RegLegacyFixups. Hive: HKCU");
                                Log("[%d] Bad Regex pattern ignored in RegLegacyFixups.\n", RegLocalInstance);
                            }
                        }
                    }
                    break;
                case Modify_Key_Hive_Type_HKLM:
                    keystring = "HKEY_LOCAL_MACHINE\\";
                    if (keypath._Starts_with(keystring))
                    {
#ifdef _DEBUG
                        Log("[%d] RegFixupSam:  is HKLM key\n", RegLocalInstance);
#endif
                        for (auto& pattern : specitem.modifyKeyAccess.patterns)
                        {
                            try
                            {
                                if (std::regex_match(widen(keypath.substr(keystring.size())), std::wregex(pattern)))
                                {
#ifdef _DEBUG
                                    Log("[%d] RegFixupSam: HKLM pattern match.\n", RegLocalInstance);
#endif
                                    switch (specitem.modifyKeyAccess.access)
                                    {
                                    case Modify_Key_Access_Type_Full2RW:
                                        if ((samDesired & (KEY_ALL_ACCESS | KEY_CREATE_LINK)) != 0)
                                        {
                                            samModified = samDesired & ~(DELETE | KEY_CREATE_LINK);
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: Full2RW\n", RegLocalInstance);
#endif
                                        }
                                        break;
                                    case Modify_Key_Access_Type_Full2R:
                                        if ((samDesired & (DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK)) != 0)
                                        {
                                            samModified = samDesired & ~(DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK);
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: Full2R\n", RegLocalInstance);
#endif
                                        }
                                    case Modify_Key_Access_Type_Full2MaxAllowed:
                                        if ((samDesired & (DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK)) != 0)
                                        {
                                            samModified = MAXIMUM_ALLOWED;
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: Full2MaxAllowed\n", RegLocalInstance);
#endif                                    
                                        }
                                    case Modify_Key_Access_Type_RW2R:
                                        if ((samDesired & (KEY_CREATE_LINK | KEY_CREATE_SUB_KEY | KEY_SET_VALUE)) != 0)
                                        {
                                            samModified = samDesired & ~(DELETE | WRITE_DAC | WRITE_OWNER | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK);
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: RW2R\n", RegLocalInstance);
#endif
                                        }
                                    case Modify_Key_Access_Type_RW2MaxAllowed:
                                        if ((samDesired & (KEY_CREATE_LINK | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | WRITE_DAC | WRITE_OWNER)) != 0)
                                        {
                                            samModified = MAXIMUM_ALLOWED;
#ifdef _DEBUG
                                            Log("[%d] RegFixupSam: RW2MaxAllowed\n", RegLocalInstance);
#endif                                    
                                        }
                                    default:
                                        break;
                                    }
                                    return samModified;
                                }
                            }
                            catch (...)
                            {
                                psf::TraceLogExceptions("RegLegacyFixupException", "Bad Regex pattern ignored in RegLegacyFixups. Hive: HKLM");
                                Log("[%d] Bad Regex pattern ignored in RegLegacyFixups.\n", RegLocalInstance);
                            }
                        }
                    }
                    break;
                case Modify_Key_Hive_Type_Unknown:
                default:
                    break;
                }
            }
        }
    }
    return samModified;
}

#ifdef _DEBUG
bool RegFixupFakeDelete(std::string keypath,DWORD RegLocalInstance)
#else
bool RegFixupFakeDelete(std::string keypath)
#endif
{
    keypath = ReplaceRegistrySyntax(keypath);
#ifdef _DEBUG
    Log("[%d] RegFixupFakeDelete: path=%s\n", RegLocalInstance, keypath.c_str());
#endif
    std::string keystring;
    for (auto& spec : g_regRemediationSpecs)
    {
#ifdef _DEBUG
        Log("[%d] RegFixupFakeDelete: spec\n", RegLocalInstance);
#endif        
        for (auto& specitem : spec.remediationRecords)
        {
#ifdef _DEBUG
            Log("[%d] RegFixupFakeDelete: specitem.type=%d\n", RegLocalInstance, specitem.remeditaionType);
#endif        
            switch (specitem.fakeDeleteKey.hive)
            {
            case Modify_Key_Hive_Type_HKCU:
                keystring = "HKEY_CURRENT_USER\\";
                if (keypath._Starts_with(keystring))
                {
                    for (auto& pattern : specitem.fakeDeleteKey.patterns)
                    {
                        try
                        {
                            if (std::regex_match(widen(keypath.substr(keystring.size())), std::wregex(pattern)))
                            {
#ifdef _DEBUG
                                Log("[%d] RegFixupFakeDelete: match hkcu\n", RegLocalInstance);
#endif                            
                                return true;
                            }
                        }
                        catch (...)
                        {
                            psf::TraceLogExceptions("RegLegacyFixupException", "RegFixupFakeDelete: Bad Regex pattern ignored in RegLegacyFixups. Hive: HKCU");
#ifdef _DEBUG
                            Log("[%d] Bad Regex pattern ignored in RegLegacyFixups.\n", RegLocalInstance);
#endif
                        }
                    }
                }
                break;
            case Modify_Key_Hive_Type_HKLM:
                keystring = "HKEY_LOCAL_MACHINE\\";
                if (keypath._Starts_with(keystring))
                {
                    for (auto& pattern : specitem.fakeDeleteKey.patterns)
                    {
                        try
                        {
                            if (std::regex_match(widen(keypath.substr(keystring.size())), std::wregex(pattern)))
                            {
#ifdef _DEBUG
                                Log("[%d] RegFixupFakeDelete: match hklm\n", RegLocalInstance);
#endif                            
                                return true;
                            }
                        }
                        catch (...)
                        {
                            psf::TraceLogExceptions("RegLegacyFixupException", "RegFixupFakeDelete: Bad Regex pattern ignored in RegLegacyFixups. Hive: HKLM");
#ifdef _DEBUG
                            Log("[%d] Bad Regex pattern ignored in RegLegacyFixups.\n", RegLocalInstance);
#endif
                        }

                    }
                }
                break;
            }
        }
    }
    return false;
}



auto RegCreateKeyExImpl = psf::detoured_string_function(&::RegCreateKeyExA, &::RegCreateKeyExW);
template <typename CharT>
LSTATUS __stdcall RegCreateKeyExFixup(
    _In_ HKEY key,
    _In_ const CharT* subKey,
    _Reserved_ DWORD reserved,
    _In_opt_ CharT* classType,
    _In_ DWORD options,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES securityAttributes,
    _Out_ PHKEY resultKey,
    _Out_opt_ LPDWORD disposition)
{
    LARGE_INTEGER TickStart, TickEnd;
    QueryPerformanceCounter(&TickStart);
    DWORD RegLocalInstance = ++g_RegIntceptInstance;

    auto entry = LogFunctionEntry();
    Log("[%d] RegCreateKeyEx:\n", RegLocalInstance);


    std::string keypath = InterpretKeyPath(key) + "\\" + InterpretStringA(subKey);
    REGSAM samModified = RegFixupSam(keypath, samDesired, RegLocalInstance);

    auto result = RegCreateKeyExImpl(key, subKey, reserved, classType, options, samModified, securityAttributes, resultKey, disposition);
    QueryPerformanceCounter(&TickEnd);

#if _DEBUG
    auto functionResult = from_win32(result);
    if (auto lock = acquire_output_lock(function_type::registry, functionResult))
    {
        try
        {
            LogKeyPath(key);
            LogString("\nSub Key", subKey);
            Log("[%d]Reserved=%d\n", RegLocalInstance, reserved);
            if (classType) LogString("\nClass", classType);
            LogRegKeyFlags(options);
            Log("\n[%d] samDesired=%s\n", RegLocalInstance, InterpretRegKeyAccess(samDesired).c_str());
            if (samDesired != samModified)
            {
                Log("[%d] ModifiedSam=%s\n", RegLocalInstance, InterpretRegKeyAccess(samModified).c_str());
            }
            LogSecurityAttributes(securityAttributes, RegLocalInstance);

            LogFunctionResult(functionResult);
            if (function_failed(functionResult))
            {
                LogWin32Error(result);
            }
            else if (disposition)
            {
                LogRegKeyDisposition(*disposition);
            }
            LogCallingModule();
        }
        catch (...)
        {
            Log("[%d] RegCreateKeyEx logging failure.\n", RegLocalInstance);
        }
    }
#endif
    return result;
}
DECLARE_STRING_FIXUP(RegCreateKeyExImpl, RegCreateKeyExFixup);


auto RegOpenKeyExImpl = psf::detoured_string_function(&::RegOpenKeyExA, &::RegOpenKeyExW);
template <typename CharT>
LSTATUS __stdcall RegOpenKeyExFixup(
    _In_ HKEY key,
    _In_ const CharT* subKey,
    _In_ DWORD options,
    _In_ REGSAM samDesired,
    _Out_ PHKEY resultKey)
{
    LARGE_INTEGER TickStart, TickEnd;
    QueryPerformanceCounter(&TickStart);
    DWORD RegLocalInstance = ++g_RegIntceptInstance;
    if (!g_regRedirectRemediationInitialized) CreateRegistryRedirectEntries();
    auto entry = LogFunctionEntry();

    Log("[%d] RegOpenKeyEx:\n", RegLocalInstance);
    std::string keypath = InterpretKeyPath(key) + "\\" + InterpretStringA(subKey);

    {
        std::string normalizedKeypath = ReplaceRegistrySyntax(keypath);
        size_t subkeyOffset = normalizedKeypath.find_first_of('\\');
        if (subkeyOffset != std::wstring_view::npos)
        {
            std::string requestedSubkey = normalizedKeypath.substr(subkeyOffset + 1);
            if (g_redirected_paths.find(requestedSubkey) != g_redirected_paths.end())
            {
                return RegOpenKeyExImpl(HKEY_CURRENT_USER, requestedSubkey.c_str(), options, samDesired, resultKey);
            }
        }
    }

    REGSAM samModified = RegFixupSam(keypath, samDesired, RegLocalInstance);

    auto result = RegOpenKeyExImpl(key, subKey, options, samModified,  resultKey);
    QueryPerformanceCounter(&TickEnd);

#if _DEBUG
    auto functionResult = from_win32(result);
    if (auto lock = acquire_output_lock(function_type::registry, functionResult))
    {
        try
        {
            LogKeyPath(key);
            LogString("\nSub Key", subKey);
            LogRegKeyFlags(options);
            Log("\n[%d] samDesired=%s\n", RegLocalInstance, InterpretRegKeyAccess(samDesired).c_str());
            if (samDesired != samModified)
            {
                Log("[%d] ModifiedSam=%s\n", RegLocalInstance, InterpretRegKeyAccess(samModified).c_str());
            }
            LogFunctionResult(functionResult);
            if (function_failed(functionResult))
            {
                LogWin32Error(result);
            }
            LogCallingModule();
        }
        catch (...)
        {
            Log("[%d] RegOpenKeyEx logging failure.\n", RegLocalInstance);
        }
    }
#endif
    return result;
}
DECLARE_STRING_FIXUP(RegOpenKeyExImpl, RegOpenKeyExFixup);



auto RegOpenKeyTransactedImpl = psf::detoured_string_function(&::RegOpenKeyTransactedA, &::RegOpenKeyTransactedW);
template <typename CharT>
LSTATUS __stdcall RegOpenKeyTransactedFixup(
    _In_ HKEY key,
    _In_opt_ const CharT* subKey,
    _In_opt_ DWORD options,         // reserved
    _In_ REGSAM samDesired,
    _Out_ PHKEY resultKey,
    _In_ HANDLE hTransaction,
    _In_ PVOID  pExtendedParameter)  // reserved
{


    LARGE_INTEGER TickStart, TickEnd;
    QueryPerformanceCounter(&TickStart);
    DWORD RegLocalInstance = ++g_RegIntceptInstance;
    if (!g_regRedirectRemediationInitialized) CreateRegistryRedirectEntries();
    auto entry = LogFunctionEntry();

#if _DEBUG
    Log("[%d] RegOpenKeyTransacted:\n", RegLocalInstance);
#endif

    std::string keypath = InterpretKeyPath(key) + "\\" + InterpretStringA(subKey);

    {
        std::string normalizedKeypath = ReplaceRegistrySyntax(keypath);
        size_t subkeyOffset = normalizedKeypath.find_first_of('\\');
        if (subkeyOffset != std::wstring_view::npos)
        {
            std::string requestedSubkey = normalizedKeypath.substr(subkeyOffset + 1);
            if (g_redirected_paths.find(requestedSubkey) != g_redirected_paths.end())
            {
                return RegOpenKeyTransactedImpl(HKEY_CURRENT_USER, requestedSubkey.c_str(), options, samDesired, resultKey, hTransaction, pExtendedParameter);
            }
        }
    }

    REGSAM samModified = RegFixupSam(keypath, samDesired, RegLocalInstance);

    auto result = RegOpenKeyTransactedImpl(key, subKey, options, samModified, resultKey, hTransaction, pExtendedParameter);
    QueryPerformanceCounter(&TickEnd);

#if _DEBUG
    auto functionResult = from_win32(result);
    if (auto lock = acquire_output_lock(function_type::registry, functionResult))
    {
        try
        {
            LogKeyPath(key);
            if (subKey) LogString("Sub Key", subKey);
            LogRegKeyFlags(options);
            Log("\n[%d] SamDesired=%s\n", RegLocalInstance, InterpretRegKeyAccess(samDesired).c_str());
            if (samDesired != samModified)
            {
                Log("[%d] ModifiedSam=%s\n", RegLocalInstance, InterpretRegKeyAccess(samModified).c_str());
            }
            LogFunctionResult(functionResult);
            if (function_failed(functionResult))
            {
                LogWin32Error(result);
            }
            LogCallingModule();
        }
        catch (...)
        {
            Log("[%d] RegOpenKeyTransacted logging failure.\n", RegLocalInstance);
        }
    }
#endif
    return result;
}
DECLARE_STRING_FIXUP(RegOpenKeyTransactedImpl, RegOpenKeyTransactedFixup);




// Also needed (but we need a Psf detour for apis other than string function pairs):
//  RegOpenClassesRoot
//  RegOpenCurrentUser

auto RegDeleteKeyImpl = psf::detoured_string_function(&::RegDeleteKeyA, &::RegDeleteKeyW);
template <typename CharT>
LSTATUS __stdcall RegDeleteKeyFixup(
    _In_ HKEY key,
    _In_ const CharT* subKey)
{

    LARGE_INTEGER TickStart, TickEnd;
    QueryPerformanceCounter(&TickStart);
    DWORD RegLocalInstance = ++g_RegIntceptInstance;
    auto entry = LogFunctionEntry();


    auto result = RegDeleteKeyImpl(key, subKey);
    auto functionResult = from_win32(result);
    QueryPerformanceCounter(&TickEnd);

    if (functionResult != from_win32(0))
    {
        if (auto lock = acquire_output_lock(function_type::registry, functionResult))
        {
            try
            {
#if _DEBUG
                Log("[%d] RegDeleteKey:\n", RegLocalInstance);
#endif
                std::string keypath = InterpretKeyPath(key) + "\\" + InterpretStringA(subKey);

#ifdef _DEBUG
                Log("[%d] RegDeleteKey: Path=%s", RegLocalInstance, keypath.c_str());
                if (RegFixupFakeDelete(keypath, RegLocalInstance) == true)
#else
                if (RegFixupFakeDelete(keypath) == true)
#endif
                {
#if _DEBUG
                    Log("[%d] RegDeleteKey:Fake Success\n", RegLocalInstance);
#endif
                    result = 0;
                    LogCallingModule();
                }
            }
            catch  (...)
            {
                Log("[%d] RegDeleteKey logging failure.\n", RegLocalInstance);
            }
        }
    }
#if _DEBUG
    Log("[%d] RegDeleteKey:Fake returns %d\n", RegLocalInstance, result);
#endif
    return result;
}
DECLARE_STRING_FIXUP(RegDeleteKeyImpl, RegDeleteKeyFixup);


auto RegDeleteKeyExImpl = psf::detoured_string_function(&::RegDeleteKeyExA, &::RegDeleteKeyExW);
template <typename CharT>
LSTATUS __stdcall RegDeleteKeyExFixup(
    _In_ HKEY key,
    _In_ const CharT* subKey,
    DWORD viewDesired, // 32/64
    DWORD Reserved)
{

    LARGE_INTEGER TickStart, TickEnd;
    QueryPerformanceCounter(&TickStart);
    DWORD RegLocalInstance = ++g_RegIntceptInstance;
    auto entry = LogFunctionEntry();


    auto result = RegDeleteKeyExImpl(key, subKey, viewDesired, Reserved);
    auto functionResult = from_win32(result);
    QueryPerformanceCounter(&TickEnd);

    if (functionResult != from_win32(0))
    {
        if (auto lock = acquire_output_lock(function_type::registry, functionResult))
        {
            try
            {
#if _DEBUG
                Log("[%d] RegDeleteKeyEx:\n", RegLocalInstance);
#endif
                std::string keypath = InterpretKeyPath(key) + "\\" + InterpretStringA(subKey);
#ifdef _DEBUG
                Log("[%d] RegDeleteKeyEx: Path=%s", RegLocalInstance, keypath.c_str());
                if (RegFixupFakeDelete(keypath, RegLocalInstance) == true)
#else
                if (RegFixupFakeDelete(keypath) == true)
#endif
                {
#if _DEBUG
                    Log("[%d] RegDeleteKeyEx:Fake Success\n", RegLocalInstance);
#endif
                    result = 0;
                    LogCallingModule();
                }
            }
            catch (...)
            {
                Log("[%d] RegDeleteKeyEx logging failure.\n", RegLocalInstance);
            }
        }
    }
#if _DEBUG
    Log("[%d] RegDeleteKeyEx:Fake returns %d\n", RegLocalInstance, result);
#endif
    return result;
}
DECLARE_STRING_FIXUP(RegDeleteKeyExImpl, RegDeleteKeyExFixup);

auto RegDeleteKeyTransactedImpl = psf::detoured_string_function(&::RegDeleteKeyTransactedA, &::RegDeleteKeyTransactedW);
template <typename CharT>
LSTATUS __stdcall RegDeleteKeyTransactedFixup(
    _In_ HKEY key,
    _In_ const CharT* subKey,
    DWORD viewDesired, // 32/64
    DWORD Reserved,
    HANDLE hTransaction,
    PVOID  pExtendedParameter)
{

    LARGE_INTEGER TickStart, TickEnd;
    QueryPerformanceCounter(&TickStart);
    DWORD RegLocalInstance = ++g_RegIntceptInstance;
    auto entry = LogFunctionEntry();


    auto result = RegDeleteKeyTransactedImpl(key, subKey, viewDesired, Reserved, hTransaction, pExtendedParameter);
    auto functionResult = from_win32(result);
    QueryPerformanceCounter(&TickEnd);

    if (functionResult != from_win32(0))
    {
        if (auto lock = acquire_output_lock(function_type::registry, functionResult))
        {
            try
            {
#if _DEBUG
                Log("[%d] RegDeleteKeyTransacted:\n", RegLocalInstance);
#endif
                std::string keypath = InterpretKeyPath(key) + "\\" + InterpretStringA(subKey);
#ifdef _DEBUG
                Log("[%d] RegDeleteKeyTransacted: Path=%s", RegLocalInstance, keypath.c_str());
                if (RegFixupFakeDelete(keypath, RegLocalInstance) == true)
#else
                if (RegFixupFakeDelete(keypath) == true)
#endif
                {
#if _DEBUG
                    Log("[%d] RegDeleteKeyTransacted:Fake Success\n", RegLocalInstance);
#endif
                    result = 0;
                    LogCallingModule();
                }
            }
            catch (...)
            {
                Log("[%d] RegDeleteKeyTransacted logging failure.\n", RegLocalInstance);
            }
        }
    }
#if _DEBUG
    Log("[%d] RegDeleteKeyTransacted:Fake returns %d\n", RegLocalInstance, result);
#endif
    return result;
}
DECLARE_STRING_FIXUP(RegDeleteKeyTransactedImpl, RegDeleteKeyTransactedFixup);


auto RegDeleteValueImpl = psf::detoured_string_function(&::RegDeleteValueA, &::RegDeleteValueW);
template <typename CharT>
LSTATUS __stdcall RegDeleteValueFixup(
    _In_ HKEY key,
    _In_ const CharT* subValueName)
{

    LARGE_INTEGER TickStart, TickEnd;
    QueryPerformanceCounter(&TickStart);
    DWORD RegLocalInstance = ++g_RegIntceptInstance;
    auto entry = LogFunctionEntry();


    auto result = RegDeleteValueImpl(key, subValueName);
    auto functionResult = from_win32(result);
    QueryPerformanceCounter(&TickEnd);

    if (functionResult != from_win32(0))
    {
        if (auto lock = acquire_output_lock(function_type::registry, functionResult))
        {
            try
            {
#if _DEBUG
                Log("[%d] RegDeleteValue:\n", RegLocalInstance);
#endif
                std::string keypath = InterpretKeyPath(key) + "\\" + InterpretStringA(subValueName);
#ifdef _DEBUG
                Log("[%d] RegDeleteValue: Path=%s", RegLocalInstance, keypath.c_str());
                if (RegFixupFakeDelete(keypath, RegLocalInstance) == true)
#else
                if (RegFixupFakeDelete(keypath) == true)
#endif
                {
#if _DEBUG
                    Log("[%d] RegDeleteValue:Fake Success\n", RegLocalInstance);
#endif
                    result = 0;
                    LogCallingModule();
                }
            }
            catch (...)
            {
                Log("[%d] RegDeleteValue logging failure.\n", RegLocalInstance);
            }
        }
    }
#if _DEBUG
    Log("[%d] RegDeleteValue:Fake returns %d\n", RegLocalInstance, result);
#endif
    return result;
}
DECLARE_STRING_FIXUP(RegDeleteValueImpl, RegDeleteValueFixup);

