#include "Include.h"
#include "yara.h"
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule) {
    genericRules.push_back({ name, rule });
}

void compiler_error_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) {
    fprintf(stderr, "YARA Compiler ");
    switch (error_level) {
    case YARA_ERROR_LEVEL_ERROR:   fprintf(stderr, "Error");   break;
    case YARA_ERROR_LEVEL_WARNING: fprintf(stderr, "Warning"); break;
    default:                       fprintf(stderr, "Message"); break;
    }
    if (file_name)    fprintf(stderr, " in %s", file_name);
    if (line_number > 0) fprintf(stderr, "(%d)", line_number);
    fprintf(stderr, ": %s\n", message);
}

int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        std::vector<std::string>* matched = static_cast<std::vector<std::string>*>(user_data);
        if (matched) matched->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// ============================================================
//  ALL DETECTION RULES
// ============================================================

void initializeGenericRules() {

// ────────────────────────────────────────────────────────────
// RULE A  –  Generic Clicker / AutoClick keywords
// ────────────────────────────────────────────────────────────
addGenericRule("Generic_A", R"(
import "pe"
rule A
{
    strings:
        $a  = /clicker/i          ascii wide
        $b  = /autoclick/i        ascii wide
        $c  = /autoclicker/i      ascii wide
        $d  = /String Cleaner/i   ascii wide
        $e  = /double_click/i     ascii wide
        $f  = /Jitter Click/i     ascii wide
        $g  = /Butterfly Click/i  ascii wide
        $h  = /jitterclick/i      ascii wide
        $i  = /dragclick/i        ascii wide
        $j  = /drag click/i       ascii wide
        $k  = /speedclick/i       ascii wide
        $l  = /rapidfire/i        ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE A2  –  Generic Hack / Cheat / Inject keywords
// ────────────────────────────────────────────────────────────
addGenericRule("Generic_A2", R"(
import "pe"
rule A2
{
    strings:
        $a  = /cheat engine/i       ascii wide
        $b  = /hack client/i        ascii wide
        $c  = /inject dll/i         ascii wide
        $d  = /dll inject/i         ascii wide
        $e  = /dll injector/i       ascii wide
        $f  = /process inject/i     ascii wide
        $g  = /memory hack/i        ascii wide
        $h  = /aimbot/i             ascii wide
        $i  = /wallhack/i           ascii wide
        $j  = /triggerbot/i         ascii wide
        $k  = /esp hack/i           ascii wide
        $l  = /spinbot/i            ascii wide
        $m  = /bunnyhop/i           ascii wide
        $n  = /bhop/i               ascii wide
        $o  = /no recoil/i          ascii wide
        $p  = /norecoil/i           ascii wide
        $q  = /rapidfire/i          ascii wide
        $r  = /speed hack/i         ascii wide
        $s  = /speedhack/i          ascii wide
        $t  = /god mode/i           ascii wide
        $u  = /godmode/i            ascii wide
        $v  = /anti-anticheat/i     ascii wide
        $w  = /bypass anticheat/i   ascii wide
        $x  = /anticheat bypass/i   ascii wide
        $y  = /cheat menu/i         ascii wide
        $z  = /hack menu/i          ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE F  –  Known Cheat Software Strings (Minecraft focus)
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_F", R"(
import "pe"
rule F
{
    strings:
        $a  = /Exodus\.codes/i              ascii wide
        $b  = /slinky\.gg/i                 ascii wide
        $c  = /slinkyhook\.dll/i            ascii wide
        $d  = /slinky_library\.dll/i        ascii wide
        $e  = /Vape Launcher/i              ascii wide
        $f  = /vape\.gg/i                   ascii wide
        $g  = /discord\.gg\/advantages/i    ascii wide
        $h  = /String cleaner/i             ascii wide
        $i  = /PE injector/i                ascii wide
        $j  = /starlight v1\.0/i            ascii wide
        $k  = /Sapphire LITE Clicker/i      ascii wide
        $l  = /Striker\.exe/i               ascii wide
        $m  = /Cracked by Kangaroo/i        ascii wide
        $n  = /Monolith Lite/i              ascii wide
        $o  = /dream-injector/i             ascii wide
        $p  = /UNICORN CLIENT/i             ascii wide
        $q  = /UwU Client/i                 ascii wide
        $r  = /lithiumclient\.wtf/i         ascii wide
        $s  = /breeze\.rip/i                ascii wide
        $t  = /breeze\.dll/i                ascii wide
        $u  = /Breeze\.InjectScreen/i       ascii wide
        $v  = /Failed injecting dll/i       ascii wide
        $w  = /Adding delay to Minecraft/i  ascii wide
        $x  = /SparkCrack\.exe/i            ascii wide
        $y  = /rightClickChk\.BackgroundImage/i ascii wide
        $z  = /The clicker code was done by Nightbot/i ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE F2  –  More Minecraft Cheat Clients
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_F2", R"(
import "pe"
rule F2
{
    strings:
        $a  = /wurst.client/i           ascii wide
        $b  = /wurstclient/i            ascii wide
        $c  = /wurst-client/i           ascii wide
        $d  = /Impact client/i          ascii wide
        $e  = /impactclient/i           ascii wide
        $f  = /Aristois/i               ascii wide
        $g  = /meteor.client/i          ascii wide
        $h  = /meteorclient/i           ascii wide
        $i  = /Future Client/i          ascii wide
        $j  = /futureclient/i           ascii wide
        $k  = /Inertia Client/i         ascii wide
        $l  = /Sigma Client/i           ascii wide
        $m  = /Liquidbounce/i           ascii wide
        $n  = /liquid.bounce/i          ascii wide
        $o  = /RusherHack/i             ascii wide
        $p  = /rusherhack/i             ascii wide
        $q  = /Wolfram Client/i         ascii wide
        $r  = /wolframclient/i          ascii wide
        $s  = /Ares Client/i            ascii wide
        $t  = /Flux Client/i            ascii wide
        $u  = /fluxclient/i             ascii wide
        $v  = /SkillClient/i            ascii wide
        $w  = /Novoline/i               ascii wide
        $x  = /novolineclient/i         ascii wide
        $y  = /Tenacity Client/i        ascii wide
        $z  = /Aura Client/i            ascii wide
        $aa = /Hurricane Client/i       ascii wide
        $ab = /Hypnotic Client/i        ascii wide
        $ac = /Raven Client/i           ascii wide
        $ad = /Entropy Client/i         ascii wide
        $ae = /Nodus client/i           ascii wide
        $af = /Atomic Client/i          ascii wide
        $ag = /Drip Client/i            ascii wide
        $ah = /Drip Lite/i              ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE G  –  CS2 / CSGO Cheat Strings
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_G", R"(
import "pe"
rule G
{
    strings:
        $a  = /client\.dll/i            ascii wide
        $b  = /engine2\.dll/i           ascii wide
        $c  = /valve anti-cheat/i       ascii wide
        $d  = /VAC bypass/i             ascii wide
        $e  = /VACbypass/i              ascii wide
        $f  = /cs2 cheat/i              ascii wide
        $g  = /csgo cheat/i             ascii wide
        $h  = /cs2hack/i                ascii wide
        $i  = /csgohack/i               ascii wide
        $j  = /aimware/i                ascii wide
        $k  = /aimware\.net/i           ascii wide
        $l  = /skeet\.cc/i              ascii wide
        $m  = /skeetcc/i                ascii wide
        $n  = /fatality\.win/i          ascii wide
        $o  = /onetap\.com/i            ascii wide
        $p  = /onetap\.su/i             ascii wide
        $q  = /gamesense\.pub/i         ascii wide
        $r  = /neverlose\.cc/i          ascii wide
        $s  = /primordial\.cc/i         ascii wide
        $t  = /pandora\.cc/i            ascii wide
        $u  = /interwebz\.cc/i          ascii wide
        $v  = /hvh cheat/i              ascii wide
        $w  = /resolver/i               ascii wide
        $x  = /anti-aim/i               ascii wide
        $y  = /antiaim/i                ascii wide
        $z  = /ragebot/i                ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE G2  –  Valorant Cheat Strings
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_G2", R"(
import "pe"
rule G2
{
    strings:
        $a  = /valorant cheat/i         ascii wide
        $b  = /valorant hack/i          ascii wide
        $c  = /valorant aimbot/i        ascii wide
        $d  = /valorant esp/i           ascii wide
        $e  = /vanguard bypass/i        ascii wide
        $f  = /vanguard spoof/i         ascii wide
        $g  = /riot vanguard/i          ascii wide
        $h  = /valorant.exe/i           ascii wide
        $i  = /VALORANT-Cheat/i         ascii wide
        $j  = /valorantcheat/i          ascii wide
        $k  = /valorant-external/i      ascii wide
        $l  = /valorant-internal/i      ascii wide
        $m  = /kernel cheat/i           ascii wide
        $n  = /kernelcheat/i            ascii wide
        $o  = /driver cheat/i           ascii wide
        $p  = /drivercheat/i            ascii wide
        $q  = /EasyAntiCheat bypass/i   ascii wide
        $r  = /EAC bypass/i             ascii wide
        $s  = /eac spoof/i              ascii wide
        $t  = /hwid spoof/i             ascii wide
        $u  = /hwidspoof/i              ascii wide
        $v  = /hwid ban/i               ascii wide
        $w  = /hwid changer/i           ascii wide
        $x  = /serial spoof/i           ascii wide
        $y  = /disk spoof/i             ascii wide
        $z  = /vmprotect bypass/i       ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE G3  –  Fortnite Cheat Strings
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_G3", R"(
import "pe"
rule G3
{
    strings:
        $a  = /fortnite cheat/i         ascii wide
        $b  = /fortnite hack/i          ascii wide
        $c  = /fortnite aimbot/i        ascii wide
        $d  = /fortnite esp/i           ascii wide
        $e  = /fortnite wallhack/i      ascii wide
        $f  = /fortnite triggerbot/i    ascii wide
        $g  = /fn cheat/i               ascii wide
        $h  = /fn hack/i                ascii wide
        $i  = /fn aimbot/i              ascii wide
        $j  = /BattlEye bypass/i        ascii wide
        $k  = /battleye bypass/i        ascii wide
        $l  = /be bypass/i              ascii wide
        $m  = /be spoof/i               ascii wide
        $n  = /FortniteBR/i             ascii wide
        $o  = /FortniteGame/i           ascii wide
        $p  = /epicgames cheat/i        ascii wide
        $q  = /launchpad\.exe/i         ascii wide
        $r  = /silent aimbot/i          ascii wide
        $s  = /silentaim/i              ascii wide
        $t  = /bone aimbot/i            ascii wide
        $u  = /boneaimbot/i             ascii wide
        $v  = /recoil script/i          ascii wide
        $w  = /recoilscript/i           ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE H  –  Exploit / Cracking / Keygen Tools
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_H", R"(
import "pe"
rule H
{
    strings:
        $a  = /keygen/i             ascii wide
        $b  = /key generator/i      ascii wide
        $c  = /crack by/i           ascii wide
        $d  = /cracked by/i         ascii wide
        $e  = /serial crack/i       ascii wide
        $f  = /license crack/i      ascii wide
        $g  = /patcher/i            ascii wide
        $h  = /NoCD crack/i         ascii wide
        $i  = /NoCD patch/i         ascii wide
        $j  = /activation crack/i   ascii wide
        $k  = /bypass license/i     ascii wide
        $l  = /license bypass/i     ascii wide
        $m  = /crackme/i            ascii wide
        $n  = /reverse engineer/i   ascii wide
        $o  = /dumped by/i          ascii wide
        $p  = /unpacked by/i        ascii wide
        $q  = /skidded by/i         ascii wide
        $r  = /nulled by/i          ascii wide
        $s  = /leaked by/i          ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE I  –  RAT / Malware / Stealer Keywords
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_I", R"(
import "pe"
rule I
{
    strings:
        $a  = /remote access trojan/i   ascii wide
        $b  = /RAT client/i             ascii wide
        $c  = /RAT server/i             ascii wide
        $d  = /keylogger/i              ascii wide
        $e  = /key logger/i             ascii wide
        $f  = /stealer/i                ascii wide
        $g  = /cookie stealer/i         ascii wide
        $h  = /password stealer/i       ascii wide
        $i  = /token stealer/i          ascii wide
        $j  = /discord token/i          ascii wide
        $k  = /discord stealer/i        ascii wide
        $l  = /grabber/i                ascii wide
        $m  = /credential dump/i        ascii wide
        $n  = /lsass dump/i             ascii wide
        $o  = /mimikatz/i               ascii wide
        $p  = /ransomware/i             ascii wide
        $q  = /crypter/i                ascii wide
        $r  = /stub crypter/i           ascii wide
        $s  = /fud crypter/i            ascii wide
        $t  = /fully undetectable/i     ascii wide
        $u  = /njrat/i                  ascii wide
        $v  = /asyncrat/i               ascii wide
        $w  = /quasarrat/i              ascii wide
        $x  = /darkcomet/i              ascii wide
        $y  = /nanocore/i               ascii wide
        $z  = /remcos/i                 ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE J  –  Process / Memory Manipulation
// ────────────────────────────────────────────────────────────
addGenericRule("Generic_J", R"(
import "pe"
rule J
{
    strings:
        $a  = /WriteProcessMemory/i     ascii wide
        $b  = /ReadProcessMemory/i      ascii wide
        $c  = /VirtualAllocEx/i         ascii wide
        $d  = /CreateRemoteThread/i     ascii wide
        $e  = /NtWriteVirtualMemory/i   ascii wide
        $f  = /NtCreateThreadEx/i       ascii wide
        $g  = /manual map/i             ascii wide
        $h  = /manualmap/i              ascii wide
        $i  = /manualmapping/i          ascii wide
        $j  = /reflective inject/i      ascii wide
        $k  = /shellcode inject/i       ascii wide
        $l  = /process hollow/i         ascii wide
        $m  = /hollowing/i              ascii wide
        $n  = /SetWindowsHookEx/i       ascii wide
        $o  = /LoadLibraryA inject/i    ascii wide
    condition:
        pe.is_pe and
        filesize <= 52428800 and
        (3 of them)
}
)");

// ────────────────────────────────────────────────────────────
// RULE K  –  HWID Spoofer / Ban Evade Tools
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_K", R"(
import "pe"
rule K
{
    strings:
        $a  = /hwid spoofer/i       ascii wide
        $b  = /hwidspoofer/i        ascii wide
        $c  = /hwid changer/i       ascii wide
        $d  = /serial spoofer/i     ascii wide
        $e  = /disk serial/i        ascii wide
        $f  = /mac spoofer/i        ascii wide
        $g  = /mac changer/i        ascii wide
        $h  = /ban evade/i          ascii wide
        $i  = /ban evasion/i        ascii wide
        $j  = /unban tool/i         ascii wide
        $k  = /registry spoof/i     ascii wide
        $l  = /guid spoof/i         ascii wide
        $m  = /volume serial/i      ascii wide
        $n  = /EFI spoof/i          ascii wide
        $o  = /bios spoof/i         ascii wide
        $p  = /smbios spoof/i       ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE L  –  Apex Legends / Warzone / Rust Cheats
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_L", R"(
import "pe"
rule L
{
    strings:
        $a  = /apex cheat/i         ascii wide
        $b  = /apex hack/i          ascii wide
        $c  = /apex aimbot/i        ascii wide
        $d  = /apex legends cheat/i ascii wide
        $e  = /warzone cheat/i      ascii wide
        $f  = /warzone hack/i       ascii wide
        $g  = /warzone aimbot/i     ascii wide
        $h  = /mw2 cheat/i          ascii wide
        $i  = /mw3 cheat/i          ascii wide
        $j  = /rust cheat/i         ascii wide
        $k  = /rust hack/i          ascii wide
        $l  = /rust esp/i           ascii wide
        $m  = /rust aimbot/i        ascii wide
        $n  = /EscapeFromTarkov/i   ascii wide
        $o  = /tarkov cheat/i       ascii wide
        $p  = /tarkov hack/i        ascii wide
        $q  = /pubg cheat/i         ascii wide
        $r  = /pubg hack/i          ascii wide
        $s  = /r6 cheat/i           ascii wide
        $t  = /rainbow six cheat/i  ascii wide
        $u  = /overwatch cheat/i    ascii wide
        $v  = /overwatch hack/i     ascii wide
        $w  = /overwatch aimbot/i   ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE M  –  Suspicious PDB Paths (known cheat devs)
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_M", R"(
import "pe"
rule M
{
    strings:
        $a  = /\\cheat\\x64\\Release\\/i       ascii wide
        $b  = /\\hack\\x64\\Release\\/i        ascii wide
        $c  = /\\inject\\x64\\Release\\/i      ascii wide
        $d  = /\\injector\\x64\\Release\\/i    ascii wide
        $e  = /\\aimbot\\x64\\Release\\/i      ascii wide
        $f  = /\\esp\\x64\\Release\\/i         ascii wide
        $g  = /\\cheat\\Release\\/i            ascii wide
        $h  = /\\hack\\Release\\/i             ascii wide
        $i  = /\\loader\\Release\\/i           ascii wide
        $j  = /client-top\\x64\\Release/i      ascii wide
        $k  = /WindowsFormsApp.*cheat/i        ascii wide
        $l  = /Desktop.*hack.*Release/i        ascii wide
        $m  = /Desktop.*cheat.*Release/i       ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE N  –  Minecraft Utility / Kill Aura / Movement Hacks
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_N", R"(
import "pe"
rule N
{
    strings:
        $a  = /KillAura/i           ascii wide
        $b  = /kill aura/i          ascii wide
        $c  = /killaura/i           ascii wide
        $d  = /CriticalHit/i        ascii wide
        $e  = /criticals/i          ascii wide
        $f  = /AutoSprint/i         ascii wide
        $g  = /NoFall/i             ascii wide
        $h  = /no fall/i            ascii wide
        $i  = /AntiKnockback/i      ascii wide
        $j  = /anti knockback/i     ascii wide
        $k  = /Scaffold/i           ascii wide
        $l  = /scaffold walk/i      ascii wide
        $m  = /FastBridge/i         ascii wide
        $n  = /fast bridge/i        ascii wide
        $o  = /Reach hack/i         ascii wide
        $p  = /reach extend/i       ascii wide
        $q  = /AntiBot/i            ascii wide
        $r  = /AutoPotion/i         ascii wide
        $s  = /auto potion/i        ascii wide
        $t  = /Velocity hack/i      ascii wide
        $u  = /VelocityHack/i       ascii wide
        $v  = /InvMove/i            ascii wide
        $w  = /Phase hack/i         ascii wide
        $x  = /FastPlace/i          ascii wide
        $y  = /AutoArmor/i          ascii wide
        $z  = /NameSpoof/i          ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE O  –  Known Cheat Loader / Injector Names
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_O", R"(
import "pe"
rule O
{
    strings:
        $a  = /xenos injector/i     ascii wide
        $b  = /xenos64/i            ascii wide
        $c  = /extreme injector/i   ascii wide
        $d  = /process hacker/i     ascii wide
        $e  = /cheat engine/i       ascii wide
        $f  = /cheatengine/i        ascii wide
        $g  = /cheat-engine/i       ascii wide
        $h  = /process monitor/i    ascii wide
        $i  = /ollydbg/i            ascii wide
        $j  = /x64dbg/i             ascii wide
        $k  = /windbg cheat/i       ascii wide
        $l  = /scylla injector/i    ascii wide
        $m  = /GuidedHacking/i      ascii wide
        $n  = /UnknownCheats/i      ascii wide
        $o  = /unknowncheats\.me/i  ascii wide
        $p  = /MPGH\.net/i          ascii wide
        $q  = /mpgh cheat/i         ascii wide
        $r  = /elitepvpers/i        ascii wide
        $s  = /hackforums/i         ascii wide
        $t  = /crack-status/i       ascii wide
        $u  = /gamehacking\.org/i   ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE P  –  Anti-Debug / Anti-Analysis Evasion
// ────────────────────────────────────────────────────────────
addGenericRule("Generic_P", R"(
import "pe"
rule P
{
    strings:
        $a  = /IsDebuggerPresent/i      ascii wide
        $b  = /CheckRemoteDebugger/i    ascii wide
        $c  = /NtQueryInformationProcess/i ascii wide
        $d  = /anti debug/i             ascii wide
        $e  = /antidebug/i              ascii wide
        $f  = /debugger detect/i        ascii wide
        $g  = /sandbox detect/i         ascii wide
        $h  = /vm detect/i              ascii wide
        $i  = /vmware detect/i          ascii wide
        $j  = /virtualbox detect/i      ascii wide
        $k  = /analysis detect/i        ascii wide
        $l  = /wireshark detect/i       ascii wide
        $m  = /fiddler detect/i         ascii wide
        $n  = /charles detect/i         ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and (3 of them)
}
)");

// ────────────────────────────────────────────────────────────
// RULE Q  –  Roblox Exploit / Script Executor
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_Q", R"(
import "pe"
rule Q
{
    strings:
        $a  = /roblox exploit/i         ascii wide
        $b  = /roblox executor/i        ascii wide
        $c  = /roblox hack/i            ascii wide
        $d  = /script executor/i        ascii wide
        $e  = /scriptexecutor/i         ascii wide
        $f  = /synapse x/i              ascii wide
        $g  = /synapsex/i               ascii wide
        $h  = /krnl exploit/i           ascii wide
        $i  = /krnl executor/i          ascii wide
        $j  = /fluxus exploit/i         ascii wide
        $k  = /scriptware/i             ascii wide
        $l  = /oxygen u/i               ascii wide
        $m  = /oxygenu/i                ascii wide
        $n  = /vega x/i                 ascii wide
        $o  = /vegax/i                  ascii wide
        $p  = /arceus x/i               ascii wide
        $q  = /arceusx/i                ascii wide
        $r  = /trigon evo/i             ascii wide
        $s  = /sirhurt/i                ascii wide
        $t  = /RbxCrash/i               ascii wide
        $u  = /Byfron bypass/i          ascii wide
        $v  = /hyperion bypass/i        ascii wide
        $w  = /roblox lua inject/i      ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE R  –  GTA V / FiveM Cheat Strings
// ────────────────────────────────────────────────────────────
addGenericRule("Specific_R", R"(
import "pe"
rule R
{
    strings:
        $a  = /gta cheat/i          ascii wide
        $b  = /gta hack/i           ascii wide
        $c  = /gta5 cheat/i         ascii wide
        $d  = /gta5 mod menu/i      ascii wide
        $e  = /mod menu/i           ascii wide
        $f  = /modmenu/i            ascii wide
        $g  = /fivem cheat/i        ascii wide
        $h  = /fivem hack/i         ascii wide
        $i  = /fivem lua/i          ascii wide
        $j  = /fivem inject/i       ascii wide
        $k  = /Eulen menu/i         ascii wide
        $l  = /Kiddions/i           ascii wide
        $m  = /modest menu/i        ascii wide
        $n  = /2Take1/i             ascii wide
        $o  = /2take1/i             ascii wide
        $p  = /Stand menu/i         ascii wide
        $q  = /Cherax/i             ascii wide
        $r  = /cheraxmenu/i         ascii wide
        $s  = /Luna Cheat/i         ascii wide
        $t  = /force multiplayer/i  ascii wide
        $u  = /online bypass/i      ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");


// ────────────────────────────────────────────────────────────
// RULE S  –  Generic Emulator / VM Bypass
// ────────────────────────────────────────────────────────────
addGenericRule("Emulator_S", R"(
import "pe"
rule S
{
    strings:
        $a  = /emulator bypass/i           ascii wide
        $b  = /emulator spoof/i            ascii wide
        $c  = /emulator detect/i           ascii wide
        $d  = /vm bypass/i                 ascii wide
        $e  = /vmware bypass/i             ascii wide
        $f  = /vmware spoof/i              ascii wide
        $g  = /virtualbox bypass/i         ascii wide
        $h  = /virtualbox spoof/i          ascii wide
        $i  = /vbox bypass/i               ascii wide
        $j  = /vbox spoof/i                ascii wide
        $k  = /hyper-v bypass/i            ascii wide
        $l  = /hyperv bypass/i             ascii wide
        $m  = /sandbox bypass/i            ascii wide
        $n  = /sandbox spoof/i             ascii wide
        $o  = /qemu bypass/i               ascii wide
        $p  = /qemu spoof/i                ascii wide
        $q  = /wine bypass/i               ascii wide
        $r  = /bochs bypass/i              ascii wide
        $s  = /parallels bypass/i          ascii wide
        $t  = /virtual machine bypass/i    ascii wide
        $u  = /antivirt/i                  ascii wide
        $v  = /anti-vm/i                   ascii wide
        $w  = /anti vm/i                   ascii wide
        $x  = /vm detection/i              ascii wide
        $y  = /vm spoof/i                  ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE S2  –  Android Emulator Bypass (BlueStacks, LDPlayer etc.)
// ────────────────────────────────────────────────────────────
addGenericRule("Emulator_S2", R"(
import "pe"
rule S2
{
    strings:
        $a  = /bluestacks bypass/i         ascii wide
        $b  = /bluestacks spoof/i          ascii wide
        $c  = /bluestacks detect/i         ascii wide
        $d  = /ldplayer bypass/i           ascii wide
        $e  = /ldplayer spoof/i            ascii wide
        $f  = /noxplayer bypass/i          ascii wide
        $g  = /nox bypass/i                ascii wide
        $h  = /memu bypass/i               ascii wide
        $i  = /memu spoof/i                ascii wide
        $j  = /gameloop bypass/i           ascii wide
        $k  = /gameloop spoof/i            ascii wide
        $l  = /tencent emulator/i          ascii wide
        $m  = /mumu bypass/i               ascii wide
        $n  = /mumu spoof/i                ascii wide
        $o  = /genymotion bypass/i         ascii wide
        $p  = /genymotion spoof/i          ascii wide
        $q  = /android emulator bypass/i   ascii wide
        $r  = /android emulator spoof/i    ascii wide
        $s  = /emulator root/i             ascii wide
        $t  = /bypass emulator check/i     ascii wide
        $u  = /skip emulator/i             ascii wide
        $v  = /emulator detection bypass/i ascii wide
        $w  = /mumuapp/i                   ascii wide
        $x  = /andyroid bypass/i           ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE S3  –  Kernel / Hypervisor Spoof (anticheat emulator tricks)
// ────────────────────────────────────────────────────────────
addGenericRule("Emulator_S3", R"(
import "pe"
rule S3
{
    strings:
        $a  = /cpuid spoof/i               ascii wide
        $b  = /cpuid patch/i               ascii wide
        $c  = /cpuid bypass/i              ascii wide
        $d  = /hypervisor spoof/i          ascii wide
        $e  = /hypervisor bypass/i         ascii wide
        $f  = /hypervisor present/i        ascii wide
        $g  = /rdtsc bypass/i              ascii wide
        $h  = /rdtsc spoof/i               ascii wide
        $i  = /tsc delta/i                 ascii wide
        $j  = /vmexit/i                    ascii wide
        $k  = /vmcall/i                    ascii wide
        $l  = /vmxon/i                     ascii wide
        $m  = /ept hook/i                  ascii wide
        $n  = /epthook/i                   ascii wide
        $o  = /kernel spoof/i              ascii wide
        $p  = /kernel bypass/i             ascii wide
        $q  = /driver spoof/i              ascii wide
        $r  = /be emulator/i               ascii wide
        $s  = /eac emulator/i              ascii wide
        $t  = /vac emulator/i              ascii wide
        $u  = /ricochet bypass/i           ascii wide
        $v  = /anticheat emulator/i        ascii wide
        $w  = /anti-cheat emulator/i       ascii wide
        $x  = /hypervisor hide/i           ascii wide
        $y  = /timing bypass/i             ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE S4  –  VM Artifact Strings (fingerprint hiding tools)
// ────────────────────────────────────────────────────────────
addGenericRule("Emulator_S4", R"(
import "pe"
rule S4
{
    strings:
        $a  = /VBoxService/i               ascii wide
        $b  = /VBoxTray/i                  ascii wide
        $c  = /VBoxMouse/i                 ascii wide
        $d  = /VBoxGuest/i                 ascii wide
        $e  = /VMwareService/i             ascii wide
        $f  = /VMwareTray/i                ascii wide
        $g  = /VMwareUser/i                ascii wide
        $h  = /vmtoolsd/i                  ascii wide
        $i  = /vmusrvc/i                   ascii wide
        $j  = /SbieDll\.dll/i              ascii wide
        $k  = /SandboxieRpcSs/i            ascii wide
        $l  = /cuckoomon/i                 ascii wide
        $m  = /cuckoo_sandbox/i            ascii wide
        $n  = /patch_vbox/i                ascii wide
        $o  = /patch_vmware/i              ascii wide
        $p  = /remove_vm_artifacts/i       ascii wide
        $q  = /hide_from_debugger/i        ascii wide
        $r  = /WIRESHARK_DETECTED/i        ascii wide
        $s  = /iDefense_CM/i               ascii wide
        $t  = /VBOX_MSR/i                  ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

// ────────────────────────────────────────────────────────────
// RULE S5  –  Mobile Game Emulator Cheat
//             (PUBG Mobile, Free Fire, CODM, ML etc.)
// ────────────────────────────────────────────────────────────
addGenericRule("Emulator_S5", R"(
import "pe"
rule S5
{
    strings:
        $a  = /pubg mobile cheat/i         ascii wide
        $b  = /pubg mobile hack/i          ascii wide
        $c  = /pubg mobile aimbot/i        ascii wide
        $d  = /pubgm cheat/i               ascii wide
        $e  = /pubgm hack/i                ascii wide
        $f  = /free fire cheat/i           ascii wide
        $g  = /free fire hack/i            ascii wide
        $h  = /freefire cheat/i            ascii wide
        $i  = /ff cheat/i                  ascii wide
        $j  = /mobile legends hack/i       ascii wide
        $k  = /mlbb hack/i                 ascii wide
        $l  = /codm cheat/i                ascii wide
        $m  = /call of duty mobile cheat/i ascii wide
        $n  = /emulator script/i           ascii wide
        $o  = /emulator macro/i            ascii wide
        $p  = /emulator aim/i              ascii wide
        $q  = /android aim assist/i        ascii wide
        $r  = /mobile aim assist/i         ascii wide
        $s  = /gyroscope hack/i            ascii wide
        $t  = /x-mode bypass/i             ascii wide
        $u  = /xmode bypass/i              ascii wide
        $v  = /game guardian/i             ascii wide
        $w  = /gameguardian/i              ascii wide
        $x  = /lucky patcher/i             ascii wide
        $y  = /luckypatcher/i              ascii wide
    condition:
        pe.is_pe and filesize <= 52428800 and any of them
}
)");

} // end initializeGenericRules()

// ============================================================
//  YARA scan implementation
// ============================================================
static std::wstring utf8_to_wstring_r(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &ws[0], len);
    return ws;
}

bool scan_with_yara(const std::string& path,
    std::vector<std::string>& matched_rules,
    YR_RULES* rules)
{
    if (!rules) return false;
    matched_rules.clear();
    std::wstring wpath = utf8_to_wstring_r(path);

    HANDLE hFile = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER filesize;
    if (!GetFileSizeEx(hFile, &filesize) || filesize.QuadPart > SIZE_MAX) {
        CloseHandle(hFile); return false;
    }
    size_t size = static_cast<size_t>(filesize.QuadPart);
    auto buffer = std::make_unique<BYTE[]>(size);

    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buffer.get(), (DWORD)size, &bytesRead, nullptr);
    CloseHandle(hFile);
    if (!ok || bytesRead != size) return false;

    yr_rules_scan_mem(rules, buffer.get(), size,
        SCAN_FLAGS_FAST_MODE, yara_callback, &matched_rules, 0);
    return !matched_rules.empty();
}

// ============================================================
//  Custom .yar file loader
// ============================================================
void initializateCustomRules() {
    std::string ownDirectory = getOwnDirectory();
    for (const auto& entry : fs::directory_iterator(ownDirectory)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".yar") continue;
        std::string filePath = entry.path().string();
        printf("Loading custom rule: %s\n", filePath.c_str());

        std::ifstream file(entry.path());
        if (!file.is_open()) { fprintf(stderr, "Cannot open: %s\n", filePath.c_str()); continue; }

        std::stringstream buf; buf << file.rdbuf();
        std::string ruleContent = buf.str();
        if (ruleContent.empty()) continue;

        YR_COMPILER* vc = nullptr;
        if (yr_compiler_create(&vc) != ERROR_SUCCESS) continue;
        yr_compiler_set_callback(vc, compiler_error_callback, nullptr);
        int errs = yr_compiler_add_string(vc, ruleContent.c_str(),
            entry.path().filename().string().c_str());
        yr_compiler_destroy(vc);

        if (errs == 0) {
            addGenericRule(entry.path().stem().string(), ruleContent);
            printf("  -> OK: %s\n", entry.path().stem().string().c_str());
        } else {
            fprintf(stderr, "  -> FAILED (%d errors): %s\n", errs, filePath.c_str());
        }
    }
}

// ────────────────────────────────────────────────────────────
// RULE S  –  Generic Emulator / VM Detection Bypass