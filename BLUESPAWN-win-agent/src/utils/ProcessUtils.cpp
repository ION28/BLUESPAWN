#include "utils/ProcessUtils.h"

#include <vector>

namespace BLUESPAWN::Agent::Util{
    std::wstring GetProcessName(_In_ HANDLE process){
        if(process && process != INVALID_HANDLE_VALUE){
            std::vector<WCHAR> name{};
            DWORD dwSize{ 0 };
            QueryFullProcessImageNameW(process, 0, name.data(), &dwSize);
            dwSize += 1;
            name.resize(dwSize);
            if(QueryFullProcessImageNameW(process, 0, name.data(), &dwSize)){
                return name.data();
            } else{
                return {};
            }
        } else{
            return {};
        }
    }
}