#pragma once

#include <optional>

#include <winrt/base.h>
#include <winrt/Windows.Management.Deployment.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Foundation.Collections.h>

// Helper for querying installed package. Should be called from packge which has
// restricted capability "packageQuery" in their Manifest

using namespace winrt::Windows::Management::Deployment;
using namespace winrt::Windows::ApplicationModel;
using namespace winrt::Windows::Foundation::Collections;

constexpr const wchar_t* MicrosoftNotepadPackageFamily = L"Microsoft.WindowsNotepad_8wekyb3d8bbwe";

struct PackageModel
{
	std::wstring pkg_name;
	std::wstring pkg_version;
	std::wstring pkg_publisher;
	std::wstring pkg_install_path;
};

inline std::optional<PackageModel> query_package_with_name(std::wstring_view pkgFalimyName)
{
    PackageManager pkgManager;
    
    auto pkg = pkgManager.FindPackageForUser(L"", pkgFalimyName);
    if (!pkg)
    {
		return std::nullopt;
	}

    PackageModel model;
    model.pkg_name = pkg.Id().Name().c_str();
    auto version = pkg.Id().Version();
    model.pkg_version = std::to_wstring(version.Major) + L"." + std::to_wstring(version.Minor) + L"." + std::to_wstring(version.Build) + L"." + std::to_wstring(version.Revision);
    model.pkg_publisher = pkg.Id().Publisher().c_str();
    model.pkg_install_path = std::wstring(pkg.EffectivePath());

    return model;
}


