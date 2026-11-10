// CleanSlate.cpp — Win32 GUI, MSVC static CRT
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <filesystem>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <chrono>
#include <winternl.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace fs = std::filesystem;

#define CLR_BG        RGB(18, 18, 24)
#define CLR_PANEL     RGB(28, 30, 38)
#define CLR_ACCENT    RGB(0, 140, 255)
#define CLR_ACCENT_HI RGB(60, 180, 255)
#define CLR_TEXT      RGB(230, 235, 245)
#define CLR_SUB       RGB(140, 150, 170)
#define CLR_DANGER    RGB(220, 60, 60)
#define CLR_SAFE      RGB(0, 200, 120)

HINSTANCE g_hInst;
HWND g_hMain, g_hScan, g_hCleanSel, g_hCleanAll, g_hSettings, g_hProgress, g_hStatus, g_hList;
std::atomic<int> g_progress{0};
std::atomic<bool> g_busy{false};

struct FoundFile {
    std::wstring path;
    unsigned long long size;
    bool selected;
};
std::vector<FoundFile> g_files;
CRITICAL_SECTION g_cs;

std::wstring GetKnownPath(KNOWNFOLDERID id) {
    PWSTR p = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) {
        std::wstring s(p);
        CoTaskMemFree(p);
        return s;
    }
    return L"";
}

std::wstring FormatSize(unsigned long long b) {
    wchar_t buf[64];
    if (b >= 1024ULL*1024*1024) swprintf_s(buf, L"%.2f GB", b/1073741824.0);
    else if (b >= 1024ULL*1024) swprintf_s(buf, L"%.2f MB", b/1048576.0);
    else if (b >= 1024)         swprintf_s(buf, L"%.2f KB", b/1024.0);
    else                        swprintf_s(buf, L"%llu B", b);
    return buf;
}

bool IsProtectedExtension(const std::wstring& ext) {
    static const wchar_t* prot[] = {
        L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx",
        L".pdf", L".txt", L".rtf", L".odt", L".csv",
        L".jpg", L".jpeg", L".png", L".gif", L".bmp", L".webp",
        L".mp3", L".mp4", L".wav", L".mkv", L".mov",
        L".zip", L".rar", L".7z",
        L".psd", L".ai", L".blend",
        L".cpp", L".h", L".py", L".cs", L".java",
    };
    for (auto p : prot) if (_wcsicmp(ext.c_str(), p) == 0) return true;
    return false;
}

bool IsScriptExtension(const std::wstring& ext) {
    static const wchar_t* list[] = {
        L".ahk", L".exe", L".dll", L".bat", L".cmd",
        L".ps1", L".js", L".vbs", L".lua", L".py",
        L".sh", L".msi", L".jar"
    };
    for (auto e : list) if (_wcsicmp(ext.c_str(), e) == 0) return true;
    return false;
}

bool IsProtectedPath(const std::wstring& path) {
    std::wstring low = path;
    for (auto& c : low) c = towlower(c);
    static const wchar_t* prot[] = {
        L"\\windows\\system32", L"\\windows\\syswow64",
        L"\\program files", L"\\programdata\\microsoft",
        L"\\appdata\\roaming\\microsoft",
        L"anticheat", L"easyanticheat", L"battleye",
        L"vanguard", L"faceit", L"ricochet",
        L"\\pc-check", L"\\system volume information"
    };
    for (auto p : prot) if (low.find(p) != std::wstring::npos) return true;
    return false;
}

void SetStatus(const std::wstring& s) {
    SetWindowTextW(g_hStatus, s.c_str());
}

void SetProgress(int v) {
    g_progress = v;
    SendMessageW(g_hProgress, PBM_SETPOS, v, 0);
}

void ScanJunk() {
    std::vector<FoundFile> hits;
    std::vector<std::wstring> roots = {
        GetKnownPath(FOLDERID_LocalAppData) + L"\\Temp",
        GetKnownPath(FOLDERID_Windows) + L"\\Temp",
    };
    int idx = 0;
    for (auto& root : roots) {
        if (root.empty() || !fs::exists(root)) { idx++; continue; }
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec)) continue;
            auto p = it->path();
            if (IsProtectedPath(p.wstring())) continue;
            if (IsProtectedExtension(p.extension().wstring())) continue;
            unsigned long long sz = it->file_size(ec);
            if (ec) continue;
            hits.push_back({ p.wstring(), sz, true });
        }
        idx++;
        SetProgress((idx * 50) / (int)roots.size());
    }
    EnterCriticalSection(&g_cs);
    g_files = std::move(hits);
    LeaveCriticalSection(&g_cs);
}

void ScanScripts() {
    std::vector<FoundFile> hits;
    std::vector<std::wstring> roots = {
        GetKnownPath(FOLDERID_Desktop),
        GetKnownPath(FOLDERID_Downloads),
        GetKnownPath(FOLDERID_Documents),
    };
    int idx = 0;
    for (auto& root : roots) {
        if (root.empty() || !fs::exists(root)) { idx++; continue; }
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec)) continue;
            auto p = it->path();
            if (!IsScriptExtension(p.extension().wstring())) continue;
            if (IsProtectedPath(p.wstring())) continue;
            unsigned long long sz = it->file_size(ec);
            if (ec) continue;
            hits.push_back({ p.wstring(), sz, false });
        }
        idx++;
        SetProgress(50 + (idx * 50) / (int)roots.size());
    }
    EnterCriticalSection(&g_cs);
    g_files.insert(g_files.end(), hits.begin(), hits.end());
    LeaveCriticalSection(&g_cs);
}

std::vector<std::wstring> BrowserCaches() {
    std::vector<std::wstring> v;
    std::wstring local = GetKnownPath(FOLDERID_LocalAppData);
    v.push_back(local + L"\\Google\\Chrome\\User Data\\Default\\Cache");
    v.push_back(local + L"\\Google\\Chrome\\User Data\\Default\\Code Cache");
    v.push_back(local + L"\\Microsoft\\Edge\\User Data\\Default\\Cache");
    v.push_back(local + L"\\Microsoft\\Edge\\User Data\\Default\\Code Cache");
    return v;
}

void RefreshList() {
    ListView_DeleteAllItems(g_hList);
    EnterCriticalSection(&g_cs);
    int i = 0;
    for (auto& f : g_files) {
        LVITEMW lv{};
        lv.mask = LVIF_TEXT;
        lv.iItem = i;
        lv.pszText = (LPWSTR)f.path.c_str();
        ListView_InsertItem(g_hList, &lv);
        ListView_SetItemText(g_hList, i, 1, (LPWSTR)FormatSize(f.size).c_str());
        ListView_SetCheckState(g_hList, i, f.selected ? TRUE : FALSE);
        i++;
    }
    LeaveCriticalSection(&g_cs);
}

void CleanSelected() {
    std::vector<std::wstring> victims;
    EnterCriticalSection(&g_cs);
    for (auto& f : g_files) if (f.selected) victims.push_back(f.path);
    LeaveCriticalSection(&g_cs);
    if (victims.empty()) { MessageBoxW(g_hMain, L"No files selected.", L"CleanSlate", MB_OK|MB_ICONINFORMATION); return; }

    std::wstring msg = L"Delete " + std::to_wstring(victims.size()) + L" file(s)?\n\nThis cannot be undone.";
    if (MessageBoxW(g_hMain, msg.c_str(), L"Confirm Delete", MB_YESNO|MB_ICONWARNING) != IDYES) return;

    int ok = 0, fail = 0, idx = 0;
    for (auto& v : victims) {
        if (IsProtectedPath(v)) { fail++; continue; }
        std::error_code ec;
        if (fs::remove(v, ec)) ok++; else fail++;
        idx++;
        SetProgress((idx * 100) / (int)victims.size());
    }
    EnterCriticalSection(&g_cs);
    g_files.erase(std::remove_if(g_files.begin(), g_files.end(),
        [&](const FoundFile& f){ return f.selected; }), g_files.end());
    LeaveCriticalSection(&g_cs);
    RefreshList();
    wchar_t buf[128];
    swprintf_s(buf, L"Deleted %d, failed %d.", ok, fail);
    SetStatus(buf);
}

void CleanAllSafe() {
    EnterCriticalSection(&g_cs);
    for (auto& f : g_files) {
        std::wstring ext = fs::path(f.path).extension().wstring();
        f.selected = !IsScriptExtension(ext);
    }
    LeaveCriticalSection(&g_cs);
    RefreshList();
    CleanSelected();
}

void ConfirmBrowserClean() {
    if (MessageBoxW(g_hMain, L"Clear Chrome and Edge cache?\n\nBrowsing history is NOT touched.",
                    L"Browser Cleaner", MB_YESNO|MB_ICONQUESTION) != IDYES) return;
    auto caches = BrowserCaches();
    int ok = 0;
    for (auto& c : caches) {
        std::error_code ec;
        if (!fs::exists(c, ec)) continue;
        for (auto& e : fs::directory_iterator(c, ec)) {
            if (ec) { ec.clear(); continue; }
            fs::remove_all(e.path(), ec);
            if (!ec) ok++;
        }
    }
    wchar_t buf[128]; swprintf_s(buf, L"Cleared %d cache item(s).", ok);
    SetStatus(buf);
}

void RunScan() {
    if (g_busy.exchange(true)) return;
    SetProgress(0);
    SetStatus(L"Scanning junk + scripts...");
    {
        EnterCriticalSection(&g_cs); g_files.clear(); LeaveCriticalSection(&g_cs);
    }
    RefreshList();
    std::thread([]{
        ScanJunk();
        ScanScripts();
        SetProgress(100);
        PostMessageW(g_hMain, WM_APP + 1, 0, 0);
        g_busy = false;
    }).detach();
}

void RunCleanSelected() {
    if (g_busy.exchange(true)) return;
    std::thread([]{
        CleanSelected();
        PostMessageW(g_hMain, WM_APP + 2, 0, 0);
        g_busy = false;
    }).detach();
}

void PaintBackground(HWND hWnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hWnd, &ps);
    RECT rc; GetClientRect(hWnd, &rc);
    HBRUSH b = CreateSolidBrush(CLR_BG);
    FillRect(hdc, &rc, b);
    DeleteObject(b);
    RECT bar = {0, 0, rc.right, 3};
    HBRUSH ab = CreateSolidBrush(CLR_ACCENT);
    FillRect(hdc, &bar, ab);
    DeleteObject(ab);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_TEXT);
    HFONT f = CreateFontW(22, 0, 0, 0, FW_BOLD, 0,0,0, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          DEFAULT_PITCH, L"Segoe UI");
    auto old = SelectObject(hdc, f);
    TextOutW(hdc, 16, 14, L"CleanSlate Cleaner", 18);
    SelectObject(hdc, old); DeleteObject(f);
    SetTextColor(hdc, CLR_SUB);
    HFONT f2 = CreateFontW(13, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH, L"Segoe UI");
    old = SelectObject(hdc, f2);
    TextOutW(hdc, 18, 42, L"Preview. Confirm. Clean.", 24);
    SelectObject(hdc, old); DeleteObject(f2);
    EndPaint(hWnd, &ps);
}

void PaintButton(HWND h, LPDRAWITEMSTRUCT dis) {
    if (dis->CtlType != ODT_BUTTON) return;
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    bool pressed = (dis->itemState & ODS_SELECTED);
    bool focused = (dis->itemState & ODS_FOCUS);
    COLORREF bg = pressed ? RGB(0, 100, 200) : CLR_ACCENT;
    COLORREF fg = RGB(255,255,255);
    HBRUSH b = CreateSolidBrush(bg);
    FillRect(hdc, &rc, b);
    DeleteObject(b);
    if (focused) {
        HPEN pen = CreatePen(PS_SOLID, 2, CLR_ACCENT_HI);
        auto old = SelectObject(hdc, pen);
        auto null = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, rc.left+1, rc.top+1, rc.right-1, rc.bottom-1);
        SelectObject(hdc, old); SelectObject(hdc, null); DeleteObject(pen);
    }
    wchar_t text[64];
    GetWindowTextW(h, text, 64);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, fg);
    HFONT f = CreateFontW(14, 0,0,0, FW_SEMIBOLD, 0,0,0, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          DEFAULT_PITCH, L"Segoe UI");
    auto old = SelectObject(hdc, f);
    DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, old); DeleteObject(f);
}

bool CheckCompat(HWND owner) {
    if (sizeof(void*) != 8) {
        MessageBoxW(owner, L"CleanSlate needs 64-bit Windows.", L"Unsupported", MB_OK|MB_ICONERROR);
        return false;
    }
    typedef LONG (WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    auto RtlGetVersion = (RtlGetVersionFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    if (RtlGetVersion) {
        RTL_OSVERSIONINFOW vi{};
        vi.dwOSVersionInfoSize = sizeof(vi);
        RtlGetVersion(&vi);
        if (vi.dwMajorVersion < 10) {
            wchar_t msg[256];
            swprintf_s(msg, L"CleanSlate supports Windows 10 and 11 only.\nDetected: %lu.%lu",
                       vi.dwMajorVersion, vi.dwMinorVersion);
            MessageBoxW(owner, msg, L"Unsupported Windows", MB_OK|MB_ICONWARNING);
            return false;
        }
    }
    return true;
}

LRESULT CALLBACK MainProc(HWND hWnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE: {
        InitializeCriticalSection(&g_cs);
        if (!CheckCompat(hWnd)) { DestroyWindow(hWnd); return -1; }

        auto makeBtn = [&](const wchar_t* txt, int x, int y, int cx, int cy){
            return CreateWindowW(L"BUTTON", txt, WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
                                 x, y, cx, cy, hWnd, nullptr, g_hInst, nullptr);
        };
        g_hScan     = makeBtn(L"Scan",           18,  78, 130, 36);
        g_hCleanSel = makeBtn(L"Clean Selected", 158, 78, 160, 36);
        g_hCleanAll = makeBtn(L"Clean All Safe", 328, 78, 160, 36);
        g_hSettings = makeBtn(L"Settings",       498, 78, 130, 36);

        g_hProgress = CreateWindowW(PROGRESS_CLASSW, L"", WS_CHILD|WS_VISIBLE,
                                    18, 126, 610, 14, hWnd, nullptr, g_hInst, nullptr);
        SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageW(g_hProgress, PBM_SETBKCOLOR, 0, (LPARAM)CLR_PANEL);
        SendMessageW(g_hProgress, PBM_SETBARCOLOR, 0, (LPARAM)CLR_ACCENT);

        g_hStatus = CreateWindowW(L"STATIC", L"Ready.", WS_CHILD|WS_VISIBLE,
                                  18, 146, 610, 22, hWnd, nullptr, g_hInst, nullptr);
        HFONT fStat = CreateFontW(13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  DEFAULT_PITCH, L"Segoe UI");
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)fStat, TRUE);

        g_hList = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                  WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS|WS_BORDER,
                                  18, 176, 610, 320, hWnd, nullptr, g_hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_hList, LVS_EX_CHECKBOXES|LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
        ListView_SetBkColor(g_hList, CLR_PANEL);
        ListView_SetTextBkColor(g_hList, CLR_PANEL);
        ListView_SetTextColor(g_hList, CLR_TEXT);
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT|LVCF_WIDTH;
        col.pszText = (LPWSTR)L"Path"; col.cx = 440;
        ListView_InsertColumn(g_hList, 0, &col);
        col.pszText = (LPWSTR)L"Size"; col.cx = 150;
        ListView_InsertColumn(g_hList, 1, &col);

        CreateWindowW(L"BUTTON", L"Browser Cleaner", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
                      18, 506, 180, 34, hWnd, (HMENU)9001, g_hInst, nullptr);
        CreateWindowW(L"BUTTON", L"Preview Selected", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
                      210, 506, 180, 34, hWnd, (HMENU)9002, g_hInst, nullptr);
        return 0;
    }
    case WM_DRAWITEM: {
        auto dis = (LPDRAWITEMSTRUCT)l;
        if (dis->CtlType == ODT_BUTTON) { PaintButton(dis->hwndItem, dis); return TRUE; }
        break;
    }
    case WM_COMMAND: {
        int id = LOWORD(w);
        HWND src = (HWND)l;
        if (src == g_hScan) RunScan();
        else if (src == g_hCleanSel) RunCleanSelected();
        else if (src == g_hCleanAll) {
            if (MessageBoxW(hWnd, L"Auto-select all non-script junk files and clean them?",
                            L"Clean All Safe", MB_YESNO|MB_ICONWARNING) == IDYES)
                CleanAllSafe();
        }
        else if (src == g_hSettings) {
            MessageBoxW(hWnd, L"Settings\n\nPortable mode: place CleanSlate.exe anywhere.\nNo registry writes.\nNo background processes.",
                        L"Settings", MB_OK|MB_ICONINFORMATION);
        }
        else if (id == 9001) ConfirmBrowserClean();
        else if (id == 9002) {
            std::wstring preview;
            EnterCriticalSection(&g_cs);
            for (auto& f : g_files) if (f.selected) preview += f.path + L"\n";
            LeaveCriticalSection(&g_cs);
            if (preview.empty()) MessageBoxW(hWnd, L"Nothing selected.", L"Preview", MB_OK);
            else MessageBoxW(hWnd, preview.c_str(), L"Preview Selected", MB_OK);
        }
        return 0;
    }
    case WM_NOTIFY: {
        auto nm = (LPNMHDR)l;
        if (nm->hwndFrom == g_hList && nm->code == LVN_ITEMCHANGED) {
            auto nv = (LPNMLISTVIEW)l;
            if ((nv->uChanged & LVIF_STATE) && (nv->uNewState & LVIS_STATEIMAGEMASK)) {
                bool chk = ((nv->uNewState >> 12) & 0xF) == 2;
                EnterCriticalSection(&g_cs);
                if (nv->iItem >= 0 && nv->iItem < (int)g_files.size())
                    g_files[nv->iItem].selected = chk;
                LeaveCriticalSection(&g_cs);
            }
        }
        return 0;
    }
    case WM_APP + 1: { RefreshList(); SetStatus(L"Scan complete."); return 0; }
    case WM_APP + 2: { RefreshList(); return 0; }
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: PaintBackground(hWnd); return 0;
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)w;
        SetTextColor(hdc, CLR_SUB);
        SetBkColor(hdc, CLR_BG);
        return (LRESULT)GetStockObject(NULL_BRUSH);
    }
    case WM_DESTROY:
        DeleteCriticalSection(&g_cs);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, w, l);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    g_hInst = hInst;
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    WNDCLASSW wc{};
    wc.lpfnWndProc = MainProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"CleanSlateWnd";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(CLR_BG);
    RegisterClassW(&wc);

    g_hMain = CreateWindowExW(0, L"CleanSlateWnd", L"CleanSlate Cleaner",
                              WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX,
                              CW_USEDEFAULT, CW_USEDEFAULT, 680, 620,
                              nullptr, nullptr, hInst, nullptr);
    if (!g_hMain) return 1;
    ShowWindow(g_hMain, nShow);
    UpdateWindow(g_hMain);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0)) { TranslateMessage(&m); DispatchMessageW(&m); }
    CoUninitialize();
    return 0;
}
