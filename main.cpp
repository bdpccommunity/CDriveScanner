#define NOMINMAX
#include "Include.h"

static std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring w(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &w[0], sz);
    return w;
}
static std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &s[0], sz, nullptr, nullptr);
    return s;
}

// ── open a file with ShellExecuteW (no cmd shell spawn) ───────────────────
static void shellOpen(const std::string& path) {
    auto wpath = utf8_to_wstring(path);
    ShellExecuteW(nullptr, L"open", wpath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

// ── HTML escaping ─────────────────────────────────────────────────────────
static std::string htmlEscape(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  o += "&amp;";  break;
            case '<':  o += "&lt;";   break;
            case '>':  o += "&gt;";   break;
            case '"':  o += "&quot;"; break;
            default:   o += c;
        }
    }
    return o;
}

// ── timestamp ─────────────────────────────────────────────────────────────
static std::string getTimestamp() {
    SYSTEMTIME st; GetLocalTime(&st);
    char buf[64];
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

YR_RULES*   g_compiled_rules  = nullptr;
bool        scanMyYara        = false;
bool        scanOwnYara       = false;
bool        scanForReplaces   = false;
bool        scanForDLLsOnly   = false;

std::mutex  cacheMutex;
std::mutex  consoleMutex;
std::mutex  replaceMutex;

void process_paths_worker(const std::vector<std::string>& paths,
                           size_t start_index, size_t end_index,
                           HANDLE hConsole)
{
    for (size_t i = start_index; i < end_index; ++i) {
        const std::string& path = paths[i];
        FileInfo info;
        bool found_in_cache = false;
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto it = fileCache.find(path);
            if (it != fileCache.end()) { info = it->second; found_in_cache = true; }
        }
        if (!found_in_cache) {
            info.exists      = file_exists(path);
            info.isDirectory = info.exists && is_directory(path);
            info.isValidMZ   = info.exists && !info.isDirectory && isMZFile(path);

            if (info.exists && info.isValidMZ) {
                info.signatureStatus = getDigitalSignature(path);
                if (info.signatureStatus != "Signed" && (scanMyYara || scanOwnYara)) {
                    if (!iequals(path, getOwnPath()))
                        scan_with_yara(path, info.matched_rules, g_compiled_rules);
                }
            }
            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                fileCache.insert_or_assign(path, info);
            }
        }

        {
            std::lock_guard<std::mutex> lock(consoleMutex);
            if (!info.exists || info.isDirectory) continue;

            if (info.isValidMZ) {
                if (info.signatureStatus == "Signed") {
                    SetConsoleTextAttribute(hConsole, 2);
                    std::cout << "[Signed]         ";
                } else if (info.signatureStatus == "Cheat Signature") {
                    SetConsoleTextAttribute(hConsole, 12);
                    std::cout << "[Cheat Sig]      ";
                } else if (info.signatureStatus == "Fake Signature") {
                    SetConsoleTextAttribute(hConsole, 12);
                    std::cout << "[Fake Sig]       ";
                } else {
                    SetConsoleTextAttribute(hConsole, 6);
                    std::cout << "[Not Signed]     ";
                }
                SetConsoleTextAttribute(hConsole, 7);
                auto wpath = utf8_to_wstring(path);
                WriteConsoleW(hConsole, wpath.c_str(), (DWORD)wpath.size(), nullptr, nullptr);
                if (!info.matched_rules.empty()) {
                    SetConsoleTextAttribute(hConsole, 12);
                    for (auto& r : info.matched_rules) std::cout << "  [YARA:" << r << "]";
                    SetConsoleTextAttribute(hConsole, 7);
                }
                if (scanForReplaces) {
                    std::string filename;
                    size_t pos = path.find_last_of("\\/");
                    filename = (pos != std::string::npos) ? path.substr(pos + 1) : path;
                    std::lock_guard<std::mutex> repl(replaceMutex);
                    FindReplace(filename);
                }
                std::cout << "\n";
            } else {
                SetConsoleTextAttribute(hConsole, 8);
                std::cout << "[Not MZ]         ";
                SetConsoleTextAttribute(hConsole, 7);
                auto wpath = utf8_to_wstring(path);
                WriteConsoleW(hConsole, wpath.c_str(), (DWORD)wpath.size(), nullptr, nullptr);
                std::cout << "\n";
            }
        }
    }
}

static void printBanner(HANDLE hConsole) {
    SetConsoleTextAttribute(hConsole, 11);
    std::cout << "\n";
    std::cout << "  +======================================================+\n";
    std::cout << "  |         C:\\ Drive Scanner  -  by espouken             |\n";
    std::cout << "  |   Scans every .exe / .dll / .sys on C: drive          |\n";
    std::cout << "  |   Checks signatures + optional YARA rules             |\n";
    std::cout << "  +======================================================+\n";
    std::cout << "\n";
    SetConsoleTextAttribute(hConsole, 7);
}

// ════════════════════════════════════════════════════════════════════════════
//  HTML REPORT
// ════════════════════════════════════════════════════════════════════════════
using EntryVec = std::vector<std::tuple<std::string, std::string, std::vector<std::string>>>;

static void writeHtmlReport(const std::string& htmlPath,
    const std::string& timestamp, size_t total,
    size_t sc, size_t uc, size_t cc, size_t fc, size_t yc,
    const EntryVec& cheat, const EntryVec& fake,
    const EntryVec& yara,  const EntryVec& unsig, const EntryVec& sig)
{
    std::ofstream f(htmlPath);
    if (!f.is_open()) return;

    // ── head + CSS ───────────────────────────────────────────────────────────
    f << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>C:\ Drive Scanner - Detection Report</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;--border:#30363d;
      --text:#e6edf3;--muted:#8b949e;
      --green:#3fb950;--yellow:#d29922;--red:#f85149;
      --orange:#e3652a;--blue:#58a6ff;--purple:#bc8cff;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',Arial,sans-serif;font-size:14px;}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:22px 36px;display:flex;align-items:center;gap:14px;}
header h1{font-size:20px;font-weight:700;color:var(--blue);}
header .meta{color:var(--muted);font-size:12px;margin-top:3px;}
.wrap{max-width:1440px;margin:0 auto;padding:28px 36px;}
/* cards */
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:28px;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:18px;text-align:center;}
.card .n{font-size:34px;font-weight:700;}
.card .l{color:var(--muted);font-size:11px;margin-top:3px;text-transform:uppercase;letter-spacing:.05em;}
.cg{border-top:3px solid var(--green);} .cg .n{color:var(--green);}
.cy{border-top:3px solid var(--yellow);}.cy .n{color:var(--yellow);}
.cr{border-top:3px solid var(--red);}  .cr .n{color:var(--red);}
.co{border-top:3px solid var(--orange);}.co .n{color:var(--orange);}
.cp{border-top:3px solid var(--purple);}.cp .n{color:var(--purple);}
/* search */
.search{margin-bottom:18px;}
.search input{width:100%;background:var(--bg2);border:1px solid var(--border);
  color:var(--text);padding:9px 14px;border-radius:8px;font-size:13px;outline:none;}
.search input:focus{border-color:var(--blue);}
/* section */
.sec{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:18px;overflow:hidden;}
.sec-hdr{padding:12px 18px;display:flex;align-items:center;gap:8px;cursor:pointer;
  border-bottom:1px solid var(--border);}
.sec-hdr h2{font-size:14px;font-weight:600;flex:1;}
.badge{font-size:11px;padding:2px 9px;border-radius:10px;font-weight:600;}
.br{background:#f8514920;color:var(--red);}
.bo{background:#e3652a20;color:var(--orange);}
.bp{background:#bc8cff20;color:var(--purple);}
.by{background:#d2992220;color:var(--yellow);}
.bg{background:#3fb95020;color:var(--green);}
.arrow{color:var(--muted);font-size:11px;}
/* table */
table{width:100%;border-collapse:collapse;}
th{background:var(--bg3);color:var(--muted);font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;padding:9px 14px;text-align:left;}
td{padding:8px 14px;border-top:1px solid var(--border);font-size:12px;word-break:break-all;}
tr:hover td{background:#ffffff05;}
.tag{display:inline-block;font-size:10px;padding:1px 6px;border-radius:4px;margin:1px;font-weight:600;}
.tr{background:#f8514928;color:var(--red);}
.to{background:#e3652a28;color:var(--orange);}
.tp{background:#bc8cff28;color:var(--purple);}
.ty{background:#d2992228;color:var(--yellow);}
.tg{background:#3fb95028;color:var(--green);}
footer{text-align:center;padding:20px;color:var(--muted);font-size:11px;
  border-top:1px solid var(--border);margin-top:12px;}
</style>
</head>
<body>
<header>
  <div>
    <h1>&#x1F4E1; C:\ Drive Scanner &mdash; Detection Report</h1>
    <div class="meta">)";
    f << htmlEscape(timestamp) << " &nbsp;|&nbsp; " << total << " files scanned</div>\n";
    f << "  </div>\n</header>\n<div class=\"wrap\">\n";

    // ── stat cards ────────────────────────────────────────────────────────────
    f << "<div class=\"cards\">\n"
      << "  <div class=\"card cg\"><div class=\"n\">" << sc << "</div><div class=\"l\">Signed</div></div>\n"
      << "  <div class=\"card cy\"><div class=\"n\">" << uc << "</div><div class=\"l\">Not Signed</div></div>\n"
      << "  <div class=\"card cr\"><div class=\"n\">" << cc << "</div><div class=\"l\">Cheat Sig</div></div>\n"
      << "  <div class=\"card co\"><div class=\"n\">" << fc << "</div><div class=\"l\">Fake Sig</div></div>\n"
      << "  <div class=\"card cp\"><div class=\"n\">" << yc << "</div><div class=\"l\">YARA Hits</div></div>\n"
      << "</div>\n";

    // ── search bar ────────────────────────────────────────────────────────────
    f << "<div class=\"search\"><input id=\"q\" type=\"text\" placeholder=\"&#128269;  Filter paths...\" oninput=\"doFilter()\"></div>\n";

    // ── section writer lambda ─────────────────────────────────────────────────
    auto writeSection = [&](const std::string& id, const std::string& title,
        const std::string& badge, const EntryVec& rows,
        const std::string& tagCls, bool collapsed)
    {
        if (rows.empty()) return;
        f << "<div class=\"sec\">\n"
          << "  <div class=\"sec-hdr\" onclick=\"tog('" << id << "')\">\n"
          << "    <h2>" << title << "</h2>\n"
          << "    <span class=\"badge " << badge << "\">" << rows.size() << " files</span>\n"
          << "    <span class=\"arrow\" id=\"a_" << id << "\">" << (collapsed?"&#9660;":"&#9650;") << "</span>\n"
          << "  </div>\n"
          << "  <div id=\"b_" << id << "\"" << (collapsed?" style=\"display:none\"":"") << ">\n"
          << "  <table><tr><th>#</th><th>Path</th><th>Status</th><th>YARA</th></tr>\n";
        size_t n = 1;
        for (auto& [p, st, yr] : rows) {
            f << "  <tr><td>" << n++ << "</td><td>" << htmlEscape(p) << "</td>"
              << "<td><span class=\"tag " << tagCls << "\">" << htmlEscape(st) << "</span></td><td>";
            if (yr.empty()) f << "<span style=\"color:var(--muted)\">-</span>";
            else for (auto& r : yr) f << "<span class=\"tag tp\">" << htmlEscape(r) << "</span> ";
            f << "</td></tr>\n";
        }
        f << "  </table></div></div>\n";
    };

    writeSection("cheat",    "&#x26A0; Cheat Signature &mdash; HIGH RISK",   "br", cheat, "tr", false);
    writeSection("fake",     "&#x26A0; Fake Signature &mdash; HIGH RISK",    "bo", fake,  "to", false);
    writeSection("yara",     "&#x1F50D; YARA Rule Hits &mdash; SUSPICIOUS",  "bp", yara,  "tp", false);
    writeSection("unsigned", "&#x1F512; Not Signed",                         "by", unsig, "ty", true);
    writeSection("signed",   "&#x2705; Signed (clean)",                      "bg", sig,   "tg", true);

    // ── JS + footer ───────────────────────────────────────────────────────────
    f << R"(
</div>
<footer>C:\ Drive Scanner &bull; made by espouken &bull; )" << htmlEscape(timestamp) << R"(</footer>
<script>
function tog(id){
  var b=document.getElementById('b_'+id),a=document.getElementById('a_'+id);
  if(b.style.display==='none'){b.style.display='';a.innerHTML='&#9650;';}
  else{b.style.display='none';a.innerHTML='&#9660;';}
}
function doFilter(){
  var q=document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('table tr').forEach(function(r){
    if(r.querySelector('th'))return;
    r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';
  });
}
</script>
</body></html>
)";
    f.close();
}

// ════════════════════════════════════════════════════════════════════════════
//  WRITE REPORT  (txt + html)
// ════════════════════════════════════════════════════════════════════════════
static void writeReport(HANDLE hConsole) {
    EntryVec sig, unsig, cheat, fake, yara;

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        for (auto& kv : fileCache) {
            if (!kv.second.exists || kv.second.isDirectory || !kv.second.isValidMZ) continue;
            auto e = std::make_tuple(kv.first, kv.second.signatureStatus, kv.second.matched_rules);
            if (!std::get<2>(e).empty())                   yara.push_back(e);
            if      (std::get<1>(e) == "Signed")           sig.push_back(e);
            else if (std::get<1>(e) == "Cheat Signature")  cheat.push_back(e);
            else if (std::get<1>(e) == "Fake Signature")   fake.push_back(e);
            else                                           unsig.push_back(e);
        }
    }

    auto byPath = [](const auto& a, const auto& b){ return std::get<0>(a) < std::get<0>(b); };
    std::sort(sig.begin(),   sig.end(),   byPath);
    std::sort(unsig.begin(), unsig.end(), byPath);
    std::sort(cheat.begin(), cheat.end(), byPath);
    std::sort(fake.begin(),  fake.end(),  byPath);
    std::sort(yara.begin(),  yara.end(),  byPath);

    std::string dir  = getOwnDirectory();
    std::string ts   = getTimestamp();
    size_t total     = sig.size() + unsig.size() + cheat.size() + fake.size();

    // ── plain-text report ────────────────────────────────────────────────────
    std::string txtPath = dir + "detection_report.txt";
    std::ofstream rep(txtPath);
    if (!rep.is_open()) { txtPath = "detection_report.txt"; rep.open(txtPath); }

    std::string div(72, '=');
    rep << div << "\n  C:\\ Drive Scanner - Detection Report\n  " << ts << "\n" << div << "\n";
    rep << "  Signed          : " << sig.size()   << "\n";
    rep << "  Not Signed      : " << unsig.size() << "\n";
    rep << "  Cheat Signature : " << cheat.size() << "\n";
    rep << "  Fake Signature  : " << fake.size()  << "\n";
    rep << "  YARA Hits       : " << yara.size()  << "\n";
    rep << div << "\n\n";

    auto sec = [&](const std::string& title, const EntryVec& vec){
        if (vec.empty()) return;
        rep << div << "\n  " << title << "  (" << vec.size() << " files)\n" << div << "\n";
        for (auto& e : vec){
            rep << "  [" << std::get<1>(e) << "]  " << std::get<0>(e);
            if (!std::get<2>(e).empty()){
                rep << "  --> YARA: ";
                for (auto& r : std::get<2>(e)) rep << "[" << r << "]";
            }
            rep << "\n";
        }
        rep << "\n";
    };
    sec("CHEAT SIGNATURE [HIGH RISK]",  cheat);
    sec("FAKE SIGNATURE  [HIGH RISK]",  fake);
    sec("YARA RULE HITS  [SUSPICIOUS]", yara);
    sec("NOT SIGNED",                   unsig);
    sec("SIGNED (clean)",               sig);
    rep.close();

    // ── HTML report ──────────────────────────────────────────────────────────
    std::string htmlPath = dir + "detection_report.html";
    writeHtmlReport(htmlPath, ts, total,
        sig.size(), unsig.size(), cheat.size(), fake.size(), yara.size(),
        cheat, fake, yara, unsig, sig);

    // ── console summary ──────────────────────────────────────────────────────
    SetConsoleTextAttribute(hConsole, 11);
    std::cout << "\n  +======================================+\n";
    std::cout <<   "  |        DETECTION SUMMARY             |\n";
    std::cout <<   "  +======================================+\n";
    SetConsoleTextAttribute(hConsole, 2);
    std::cout << "  Signed          : " << sig.size()   << "\n";
    SetConsoleTextAttribute(hConsole, 6);
    std::cout << "  Not Signed      : " << unsig.size() << "\n";
    SetConsoleTextAttribute(hConsole, 12);
    std::cout << "  Cheat Signature : " << cheat.size() << "\n";
    std::cout << "  Fake Signature  : " << fake.size()  << "\n";
    SetConsoleTextAttribute(hConsole, 13);
    std::cout << "  YARA Hits       : " << yara.size()  << "\n";
    SetConsoleTextAttribute(hConsole, 14);
    std::cout << "\n  [TXT]  " << txtPath  << "\n";
    std::cout <<   "  [HTML] " << htmlPath << "\n\n";
    SetConsoleTextAttribute(hConsole, 7);

    // ShellExecuteW — no cmd shell, no std::system
    shellOpen(htmlPath);
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleA("C:\\ Drive Scanner  -  made by espouken");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    printBanner(hConsole);

    if (!privilege("SeDebugPrivilege")) {
        SetConsoleTextAttribute(hConsole, 12);
        std::cout << "  [!] Failed to acquire SeDebugPrivilege.\n"
                  << "      Please run as Administrator.\n";
        SetConsoleTextAttribute(hConsole, 7);
        std::cout << "\n  Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    auto ask = [&](const std::string& q) -> bool {
        SetConsoleTextAttribute(hConsole, 14);
        std::cout << "  " << q << " (Y/N): ";
        SetConsoleTextAttribute(hConsole, 7);
        std::string in; std::getline(std::cin, in);
        return (in == "Y" || in == "y");
    };

    scanMyYara      = ask("Scan with built-in YARA rules?");
    scanOwnYara     = ask("Scan with your own .yar files?");
    scanForReplaces = ask("Check for file replacements?");
    std::cout << "\n";

    if (yr_initialize() != ERROR_SUCCESS) {
        SetConsoleTextAttribute(hConsole, 12);
        std::cerr << "  [!] Failed to initialize YARA.\n";
        SetConsoleTextAttribute(hConsole, 7);
        std::cin.get();
        return 1;
    }

    if (scanMyYara)  initializeGenericRules();
    if (scanOwnYara) initializateCustomRules();

    if (scanMyYara || scanOwnYara) {
        YR_COMPILER* compiler = nullptr;
        yr_compiler_create(&compiler);
        yr_compiler_set_callback(compiler, compiler_error_callback, nullptr);
        for (auto& r : genericRules)
            yr_compiler_add_string(compiler, r.rule.c_str(), r.name.c_str());
        yr_compiler_get_rules(compiler, &g_compiled_rules);
        yr_compiler_destroy(compiler);
        SetConsoleTextAttribute(hConsole, 10);
        std::cout << "  [+] YARA rules compiled OK.\n\n";
        SetConsoleTextAttribute(hConsole, 7);
    }

    if (scanForReplaces) {
        initReplaceParser();
        PreProcessReplacements(replaceParserDir + "\\replaces.txt");
    }

    auto paths = getAllTargetPaths();
    if (paths.empty()) {
        SetConsoleTextAttribute(hConsole, 12);
        std::cout << "  [!] No .exe/.dll/.sys files found on C:\\\n";
        SetConsoleTextAttribute(hConsole, 7);
        if (g_compiled_rules) yr_rules_destroy(g_compiled_rules);
        yr_finalize();
        std::cin.get();
        return 1;
    }

    unsigned num_threads = std::max(1u, std::thread::hardware_concurrency());
    size_t   total       = paths.size();
    size_t   per         = (total + num_threads - 1) / num_threads;

    SetConsoleTextAttribute(hConsole, 11);
    std::cout << "  Processing " << total << " files  |  " << num_threads << " threads\n\n";
    SetConsoleTextAttribute(hConsole, 7);

    std::vector<std::thread> workers;
    size_t idx = 0;
    for (unsigned t = 0; t < num_threads && idx < total; ++t) {
        size_t end = std::min(idx + per, total);
        workers.emplace_back(process_paths_worker, std::cref(paths), idx, end, hConsole);
        idx = end;
    }
    for (auto& w : workers) if (w.joinable()) w.join();

    SetConsoleTextAttribute(hConsole, 10);
    std::cout << "\n  [+] All files processed.\n";
    SetConsoleTextAttribute(hConsole, 7);

    if (scanForReplaces) {
        DestroyReplaceParser();
        WriteAllReplacementsToFileAndPrintSummary();
    }

    writeReport(hConsole);

    if (g_compiled_rules) { yr_rules_destroy(g_compiled_rules); g_compiled_rules = nullptr; }
    yr_finalize();

    SetConsoleTextAttribute(hConsole, 11);
    std::cout << "  --------------- Scan Complete ---------------\n";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "  Press Enter to exit...";
    std::cin.get();
    return 0;
}
