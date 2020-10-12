#include "utils/ProcessUtils.h"

#include <vector>

namespace BLUESPAWN::Agent::Util{
    std::wstring GetProcessName(_In_ HANDLE process){
        if(process && process != INVALID_HANDLE_VALUE){
            std::vector<WCHAR> name(MAX_PATH);
            DWORD dwSize{ 260 };
            while(!QueryFullProcessImageNameW(process, 0, name.data(), &dwSize) && GetLastError() == 0x7a){
                dwSize *= 2;
                name.resize(dwSize);
            }
            if(*name.data()){
                return name.data();
            } else{
                return {};
            }
        } else{
            return {};
        }
    }
}