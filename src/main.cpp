#include "PCH.h"

#include <fmt/format.h>

namespace logger = SKSE::log;
using namespace std::literals;

namespace UCA
{
    namespace
    {
        constexpr std::size_t kAVO_GetActorValue = 0x01;
        constexpr std::size_t kAVO_ModActorValue = 0x05;
        constexpr std::size_t kActor_KillImpl = 0x10E;
        constexpr std::size_t kIntegrityBytes = 32;

        struct Config
        {
            bool playerHasAbsoluteDamage{ true };
            bool logHealth{ true };
            bool logKillIntegrity{ true };
            float directDamage{ 1000.0F };
            std::uint32_t cooldownMs{ 250 };
        };

        Config g_config;

        std::filesystem::path GetIniPath()
        {
            return std::filesystem::path{ "Data" } /
                   "SKSE" /
                   "Plugins" /
                   "UniversalCombatArbiter.ini";
        }

        std::string ReadIniString(
            const char* a_key,
            const char* a_default = "")
        {
            std::array<char, 512> buffer{};
            const auto path = GetIniPath().string();

            ::GetPrivateProfileStringA(
                "General",
                a_key,
                a_default,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                path.c_str());

            return buffer.data();
        }

        bool ReadIniBool(
            const char* a_key,
            bool a_default)
        {
            const auto raw =
                ReadIniString(
                    a_key,
                    a_default ? "1" : "0");

            return raw == "1" ||
                   raw == "true" ||
                   raw == "TRUE" ||
                   raw == "yes" ||
                   raw == "YES";
        }

        std::uint32_t ReadIniUInt(
            const char* a_key,
            std::uint32_t a_default)
        {
            const auto raw =
                ReadIniString(
                    a_key,
                    std::to_string(a_default).c_str());

            try {
                const auto value =
                    std::stoul(raw, nullptr, 0);

                return static_cast<std::uint32_t>(
                    std::min<unsigned long>(
                        value,
                        std::numeric_limits<std::uint32_t>::max()));
            } catch (...) {
                return a_default;
            }
        }

        float ReadIniFloat(
            const char* a_key,
            float a_default)
        {
            const auto raw =
                ReadIniString(
                    a_key,
                    fmt::format("{}", a_default).c_str());

            try {
                return std::stof(raw);
            } catch (...) {
                return a_default;
            }
        }

        void LoadConfig()
        {
            g_config.playerHasAbsoluteDamage =
                ReadIniBool(
                    "bPlayerHasAbsoluteDamage",
                    true);

            g_config.logHealth =
                ReadIniBool(
                    "bLogDirectHealth",
                    true);

            g_config.logKillIntegrity =
                ReadIniBool(
                    "bLogKillIntegrity",
                    true);

            g_config.directDamage =
                std::max(
                    0.0F,
                    ReadIniFloat(
                        "fDirectDamage",
                        1000.0F));

            g_config.cooldownMs =
                std::clamp(
                    ReadIniUInt(
                        "iDirectDamageCooldownMs",
                        250),
                    0u,
                    5000u);

            logger::info(
                "Kill-Integrity PoC config: player={}, damage={}, cooldown={}ms, logHealth={}, integrity={}",
                g_config.playerHasAbsoluteDamage,
                g_config.directDamage,
                g_config.cooldownMs,
                g_config.logHealth,
                g_config.logKillIntegrity);
        }

        struct AddressInfo
        {
            std::uintptr_t address{};
            std::uintptr_t moduleBase{};
            std::uintptr_t offset{};
            std::string moduleName{ "<non-module>" };
        };

        AddressInfo DescribeAddress(
            std::uintptr_t a_address)
        {
            AddressInfo result{};
            result.address = a_address;

            if (!a_address) {
                result.moduleName = "<null>";
                return result;
            }

            MEMORY_BASIC_INFORMATION mbi{};

            if (::VirtualQuery(
                    reinterpret_cast<const void*>(a_address),
                    &mbi,
                    sizeof(mbi)) == 0 ||
                !mbi.AllocationBase) {

                return result;
            }

            result.moduleBase =
                reinterpret_cast<std::uintptr_t>(
                    mbi.AllocationBase);

            result.offset =
                a_address - result.moduleBase;

            std::array<char, 32768> path{};

            const auto count =
                ::GetModuleFileNameA(
                    reinterpret_cast<HMODULE>(
                        mbi.AllocationBase),
                    path.data(),
                    static_cast<DWORD>(
                        path.size()));

            if (count > 0 &&
                count < path.size()) {

                result.moduleName =
                    std::filesystem::path{
                        path.data()
                    }.filename().string();
            }

            return result;
        }

        std::string FormatAddress(
            std::uintptr_t a_address)
        {
            const auto info =
                DescribeAddress(a_address);

            if (info.moduleBase) {
                return fmt::format(
                    "{}+0x{:X} [0x{:X}]",
                    info.moduleName,
                    info.offset,
                    info.address);
            }

            return fmt::format(
                "{} [0x{:X}]",
                info.moduleName,
                info.address);
        }

        class PristineImage
        {
        public:
            bool Load()
            {
                const auto module =
                    ::GetModuleHandleW(nullptr);

                if (!module) {
                    logger::error(
                        "GetModuleHandleW(nullptr) failed");
                    return false;
                }

                _runtimeBase =
                    reinterpret_cast<std::uintptr_t>(
                        module);

                std::array<wchar_t, 32768> path{};

                const auto count =
                    ::GetModuleFileNameW(
                        module,
                        path.data(),
                        static_cast<DWORD>(
                            path.size()));

                if (count == 0 ||
                    count >= path.size()) {

                    logger::error(
                        "GetModuleFileNameW failed");
                    return false;
                }

                std::ifstream input(
                    std::filesystem::path{
                        path.data()
                    },
                    std::ios::binary |
                        std::ios::ate);

                if (!input) {
                    logger::error(
                        "Could not open Skyrim executable on disk");
                    return false;
                }

                const auto size =
                    input.tellg();

                if (size <= 0) {
                    return false;
                }

                _bytes.resize(
                    static_cast<std::size_t>(
                        size));

                input.seekg(
                    0,
                    std::ios::beg);

                input.read(
                    reinterpret_cast<char*>(
                        _bytes.data()),
                    static_cast<std::streamsize>(
                        size));

                if (!input) {
                    logger::error(
                        "Could not read Skyrim executable");
                    return false;
                }

                if (_bytes.size() <
                    sizeof(IMAGE_DOS_HEADER)) {

                    return false;
                }

                const auto* dos =
                    reinterpret_cast<
                        const IMAGE_DOS_HEADER*>(
                            _bytes.data());

                if (dos->e_magic !=
                        IMAGE_DOS_SIGNATURE ||
                    dos->e_lfanew <= 0) {

                    return false;
                }

                if (static_cast<std::size_t>(
                        dos->e_lfanew) +
                        sizeof(
                            IMAGE_NT_HEADERS64) >
                    _bytes.size()) {

                    return false;
                }

                const auto* nt =
                    reinterpret_cast<
                        const IMAGE_NT_HEADERS64*>(
                            _bytes.data() +
                            dos->e_lfanew);

                if (nt->Signature !=
                        IMAGE_NT_SIGNATURE ||
                    nt->OptionalHeader.Magic !=
                        IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

                    return false;
                }

                _preferredBase =
                    static_cast<std::uintptr_t>(
                        nt->OptionalHeader.ImageBase);

                _sizeOfImage =
                    nt->OptionalHeader.SizeOfImage;

                _sizeOfHeaders =
                    nt->OptionalHeader.SizeOfHeaders;

                const auto* first =
                    IMAGE_FIRST_SECTION(nt);

                _sections.assign(
                    first,
                    first +
                        nt->FileHeader
                            .NumberOfSections);

                logger::info(
                    "Pristine executable loaded: runtimeBase=0x{:X}, preferredBase=0x{:X}, imageSize=0x{:X}",
                    _runtimeBase,
                    _preferredBase,
                    _sizeOfImage);

                return true;
            }

            [[nodiscard]]
            std::uintptr_t ResolveVFunc(
                std::uintptr_t a_runtimeVTable,
                std::size_t a_slot) const
            {
                if (!_runtimeBase ||
                    _bytes.empty() ||
                    a_runtimeVTable <
                        _runtimeBase) {

                    return 0;
                }

                const auto vtableRva =
                    a_runtimeVTable -
                    _runtimeBase;

                const auto entryRva =
                    vtableRva +
                    a_slot *
                        sizeof(std::uintptr_t);

                const auto fileOffset =
                    RvaToFileOffset(
                        entryRva);

                if (!fileOffset ||
                    *fileOffset +
                        sizeof(std::uint64_t) >
                    _bytes.size()) {

                    return 0;
                }

                std::uint64_t preferredVA = 0;

                std::memcpy(
                    &preferredVA,
                    _bytes.data() +
                        *fileOffset,
                    sizeof(preferredVA));

                if (preferredVA <
                        _preferredBase ||
                    preferredVA >=
                        (_preferredBase +
                         _sizeOfImage)) {

                    return 0;
                }

                return _runtimeBase +
                       static_cast<std::uintptr_t>(
                           preferredVA -
                           _preferredBase);
            }

            [[nodiscard]]
            bool ReadRuntimeMappedBytes(
                std::uintptr_t a_runtimeAddress,
                void* a_output,
                std::size_t a_count) const
            {
                if (!_runtimeBase ||
                    _bytes.empty() ||
                    !a_output ||
                    a_count == 0 ||
                    a_runtimeAddress <
                        _runtimeBase) {

                    return false;
                }

                const auto rva =
                    a_runtimeAddress -
                    _runtimeBase;

                const auto fileOffset =
                    RvaToFileOffset(
                        rva);

                if (!fileOffset ||
                    *fileOffset + a_count >
                        _bytes.size()) {

                    return false;
                }

                std::memcpy(
                    a_output,
                    _bytes.data() +
                        *fileOffset,
                    a_count);

                return true;
            }

        private:
            [[nodiscard]]
            std::optional<std::size_t>
            RvaToFileOffset(
                std::uintptr_t a_rva) const
            {
                if (a_rva <
                    _sizeOfHeaders) {

                    return static_cast<std::size_t>(
                        a_rva);
                }

                for (const auto& section :
                     _sections) {

                    const auto begin =
                        static_cast<std::uintptr_t>(
                            section.VirtualAddress);

                    const auto span =
                        static_cast<std::uintptr_t>(
                            std::max(
                                section.Misc.VirtualSize,
                                section.SizeOfRawData));

                    if (a_rva >= begin &&
                        a_rva < begin + span) {

                        const auto delta =
                            a_rva - begin;

                        if (delta >=
                            section.SizeOfRawData) {

                            return std::nullopt;
                        }

                        return static_cast<std::size_t>(
                            section.PointerToRawData +
                            delta);
                    }
                }

                return std::nullopt;
            }

            std::vector<std::byte> _bytes{};
            std::vector<IMAGE_SECTION_HEADER> _sections{};
            std::uintptr_t _runtimeBase{};
            std::uintptr_t _preferredBase{};
            std::uintptr_t _sizeOfImage{};
            std::uintptr_t _sizeOfHeaders{};
        };

        PristineImage g_pristine;

        using GetActorValue_t =
            float (*)(
                RE::ActorValueOwner*,
                RE::ActorValue);

        using ModActorValue_t =
            void (*)(
                RE::ActorValueOwner*,
                RE::ActorValue,
                float);

        GetActorValue_t g_vanillaGetActorValue{};
        ModActorValue_t g_vanillaModActorValue{};

        std::uintptr_t g_killImplCurrent{};
        std::uintptr_t g_killImplPristine{};
        bool g_killImplBytesEqual{ false };
        bool g_integrityResolved{ false };

        bool g_bypassReady{ false };
        bool g_hitSinkRegistered{ false };

        std::mutex g_hitMutex;
        std::unordered_map<
            RE::FormID,
            ULONGLONG> g_lastHitByTarget;

        bool ShouldQueueTarget(
            RE::FormID a_formID)
        {
            if (!a_formID) {
                return false;
            }

            const auto now =
                ::GetTickCount64();

            std::scoped_lock lock{
                g_hitMutex
            };

            const auto it =
                g_lastHitByTarget.find(
                    a_formID);

            if (it !=
                g_lastHitByTarget.end()) {

                const auto elapsed =
                    now - it->second;

                if (elapsed <
                    g_config.cooldownMs) {

                    return false;
                }

                it->second = now;
                return true;
            }

            g_lastHitByTarget.emplace(
                a_formID,
                now);

            return true;
        }

        template <std::size_t N>
        std::string FormatBytes(
            const std::array<std::uint8_t, N>& a_bytes,
            std::size_t a_count = N)
        {
            const auto count =
                std::min<std::size_t>(
                    a_count,
                    N);

            std::string out;
            out.reserve(
                count * 3);

            for (std::size_t i = 0;
                 i < count;
                 ++i) {

                if (i != 0) {
                    out += ' ';
                }

                out += fmt::format(
                    "{:02X}",
                    a_bytes[i]);
            }

            return out;
        }

        std::string DescribeEntryTransfer(
            std::uintptr_t a_address,
            const std::array<
                std::uint8_t,
                kIntegrityBytes>& a_bytes)
        {
            // E9 rel32
            if (a_bytes[0] == 0xE9) {
                std::int32_t rel = 0;

                std::memcpy(
                    &rel,
                    a_bytes.data() + 1,
                    sizeof(rel));

                const auto target =
                    static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(
                            a_address + 5) +
                        static_cast<std::intptr_t>(
                            rel));

                return fmt::format(
                    "E9->{}",
                    FormatAddress(
                        target));
            }

            // FF 25 rel32  => jmp qword ptr [rip+rel32]
            if (a_bytes[0] == 0xFF &&
                a_bytes[1] == 0x25) {

                std::int32_t rel = 0;

                std::memcpy(
                    &rel,
                    a_bytes.data() + 2,
                    sizeof(rel));

                const auto slot =
                    static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(
                            a_address + 6) +
                        static_cast<std::intptr_t>(
                            rel));

                std::uintptr_t target = 0;

                MEMORY_BASIC_INFORMATION mbi{};

                if (::VirtualQuery(
                        reinterpret_cast<
                            const void*>(
                                slot),
                        &mbi,
                        sizeof(mbi)) != 0 &&
                    mbi.State == MEM_COMMIT &&
                    (mbi.Protect &
                     (PAGE_NOACCESS |
                      PAGE_GUARD)) == 0) {

                    target =
                        *reinterpret_cast<
                            const std::uintptr_t*>(
                                slot);
                }

                if (target) {
                    return fmt::format(
                        "FF25 slot=0x{:X}->{}",
                        slot,
                        FormatAddress(
                            target));
                }

                return fmt::format(
                    "FF25 slot=0x{:X}",
                    slot);
            }

            return "<no-obvious-entry-jump>";
        }

        void ResolveKillImplIntegrity()
        {
            if (g_integrityResolved ||
                !g_config.logKillIntegrity) {

                return;
            }

            static REL::Relocation<
                std::uintptr_t>
                actorVTable{
                    RE::VTABLE_Actor[0]
                };

            const auto actorVT =
                actorVTable.address();

            if (!actorVT) {
                logger::warn(
                    "[kill-integrity] Actor vtable unavailable");
                return;
            }

            g_killImplCurrent =
                *reinterpret_cast<
                    const std::uintptr_t*>(
                        actorVT +
                        kActor_KillImpl *
                            sizeof(void*));

            g_killImplPristine =
                g_pristine.ResolveVFunc(
                    actorVT,
                    kActor_KillImpl);

            if (!g_killImplCurrent ||
                !g_killImplPristine) {

                logger::warn(
                    "[kill-integrity] could not resolve KillImpl current/pristine addresses");
                return;
            }

            std::array<
                std::uint8_t,
                kIntegrityBytes>
                runtimeBytes{};

            std::array<
                std::uint8_t,
                kIntegrityBytes>
                diskBytes{};

            std::memcpy(
                runtimeBytes.data(),
                reinterpret_cast<
                    const void*>(
                        g_killImplCurrent),
                runtimeBytes.size());

            const bool diskOK =
                g_pristine.ReadRuntimeMappedBytes(
                    g_killImplPristine,
                    diskBytes.data(),
                    diskBytes.size());

            g_killImplBytesEqual =
                diskOK &&
                runtimeBytes ==
                    diskBytes;

            logger::info(
                "[kill-integrity] Actor vtable=0x{:X}[0x{:X}] current={} pristine={} sameAddress={}",
                actorVT,
                kActor_KillImpl,
                FormatAddress(
                    g_killImplCurrent),
                FormatAddress(
                    g_killImplPristine),
                g_killImplCurrent ==
                    g_killImplPristine);

            logger::info(
                "[kill-integrity] runtime32=[{}]",
                FormatBytes(
                    runtimeBytes));

            if (diskOK) {
                logger::info(
                    "[kill-integrity] disk32=[{}]",
                    FormatBytes(
                        diskBytes));

                logger::info(
                    "[kill-integrity] bytesEqual={} entryTransfer={}",
                    g_killImplBytesEqual,
                    DescribeEntryTransfer(
                        g_killImplCurrent,
                        runtimeBytes));
            } else {
                logger::warn(
                    "[kill-integrity] disk byte mapping failed");
            }

            g_integrityResolved = true;
        }

        struct ProtectionSources
        {
            bool runtimeEssential{};
            bool runtimeProtected{};
            bool baseEssential{};
            bool baseProtected{};
            RE::FormID baseForm{};
        };

        ProtectionSources ReadProtectionSources(
            RE::Actor* a_actor)
        {
            ProtectionSources result{};

            if (!a_actor) {
                return result;
            }

            result.runtimeEssential =
                a_actor->IsEssential();

            result.runtimeProtected =
                a_actor->IsProtected();

            auto* base =
                a_actor->GetActorBase();

            if (!base) {
                return result;
            }

            result.baseForm =
                base->GetFormID();

            result.baseEssential =
                base->actorData.actorBaseFlags.any(
                    RE::ACTOR_BASE_DATA::Flag::
                        kEssential);

            result.baseProtected =
                base->actorData.actorBaseFlags.any(
                    RE::ACTOR_BASE_DATA::Flag::
                        kProtected);

            return result;
        }

        std::uint32_t GetLifeStateRaw(
            RE::Actor* a_actor)
        {
            if (!a_actor) {
                return 0xFFFFFFFFu;
            }

            auto* state =
                a_actor->AsActorState();

            if (!state) {
                return 0xFFFFFFFFu;
            }

            return static_cast<std::uint32_t>(
                state->GetLifeState());
        }

        std::uintptr_t
        DiscoverLiveActorAVOVTable()
        {
            auto* player =
                RE::PlayerCharacter::
                    GetSingleton();

            auto* avo =
                player ?
                    player
                        ->AsActorValueOwner() :
                    nullptr;

            if (!player ||
                !avo) {

                return 0;
            }

            return *reinterpret_cast<
                const std::uintptr_t*>(
                    avo);
        }

        bool ResolveBypassFunctions()
        {
            ResolveKillImplIntegrity();

            if (g_bypassReady) {
                return true;
            }

            const auto liveAVOVT =
                DiscoverLiveActorAVOVTable();

            if (!liveAVOVT) {
                logger::warn(
                    "[direct-av] live Actor::ActorValueOwner vtable unavailable");
                return false;
            }

            const auto currentMod =
                *reinterpret_cast<
                    const std::uintptr_t*>(
                        liveAVOVT +
                        kAVO_ModActorValue *
                            sizeof(void*));

            const auto pristineGet =
                g_pristine.ResolveVFunc(
                    liveAVOVT,
                    kAVO_GetActorValue);

            const auto pristineMod =
                g_pristine.ResolveVFunc(
                    liveAVOVT,
                    kAVO_ModActorValue);

            logger::info(
                "[direct-av] live vtable=0x{:X}; current ModActorValue={}; pristine GetActorValue={}; pristine ModActorValue={}",
                liveAVOVT,
                FormatAddress(
                    currentMod),
                pristineGet ?
                    FormatAddress(
                        pristineGet) :
                    std::string{
                        "<unavailable>"
                    },
                pristineMod ?
                    FormatAddress(
                        pristineMod) :
                    std::string{
                        "<unavailable>"
                    });

            if (!pristineGet ||
                !pristineMod) {

                logger::error(
                    "[direct-av] could not recover pristine ActorValueOwner functions");
                return false;
            }

            g_vanillaGetActorValue =
                reinterpret_cast<
                    GetActorValue_t>(
                        pristineGet);

            g_vanillaModActorValue =
                reinterpret_cast<
                    ModActorValue_t>(
                        pristineMod);

            g_bypassReady = true;

            logger::info(
                "[direct-av] universal direct-AV bypass ready");

            return true;
        }

        void ApplyDirectDamage(
            RE::ObjectRefHandle a_targetHandle,
            RE::FormID a_targetForm,
            RE::FormID a_sourceForm,
            std::uint64_t a_hitID)
        {
            if (!g_bypassReady ||
                !g_vanillaModActorValue) {

                logger::warn(
                    "[direct-av:{}] skipped: bypass not ready",
                    a_hitID);
                return;
            }

            auto targetRef =
                a_targetHandle.get();

            if (!targetRef) {
                logger::info(
                    "[direct-av:{}] skipped: target handle expired",
                    a_hitID);
                return;
            }

            auto* actor =
                targetRef->As<RE::Actor>();

            if (!actor) {
                logger::info(
                    "[direct-av:{}] skipped: target 0x{:08X} is not Actor",
                    a_hitID,
                    a_targetForm);
                return;
            }

            auto* avo =
                actor->AsActorValueOwner();

            if (!avo) {
                logger::warn(
                    "[direct-av:{}] skipped: ActorValueOwner unavailable for 0x{:08X}",
                    a_hitID,
                    a_targetForm);
                return;
            }

            const float amount =
                -g_config.directDamage;

            std::optional<float> before;

            if (g_config.logHealth &&
                g_vanillaGetActorValue) {

                before =
                    g_vanillaGetActorValue(
                        avo,
                        RE::ActorValue::kHealth);
            }

            logger::info(
                "[direct-av:{}] APPLY target=0x{:08X} source=0x{:08X} amount={} tid={}",
                a_hitID,
                a_targetForm,
                a_sourceForm,
                amount,
                ::GetCurrentThreadId());

            // The experiment:
            // Call Bethesda's pristine ActorValueOwner::ModActorValue
            // implementation directly.  This deliberately bypasses the
            // current ActorValueOwner vtable, whatever currently owns it.
            g_vanillaModActorValue(
                avo,
                RE::ActorValue::kHealth,
                amount);

            std::optional<float> after;

            if (g_config.logHealth &&
                g_vanillaGetActorValue) {

                after =
                    g_vanillaGetActorValue(
                        avo,
                        RE::ActorValue::kHealth);
            }

            const auto lifeState =
                GetLifeStateRaw(
                    actor);

            if (before &&
                after) {

                logger::info(
                    "[direct-av:{}] RETURN target=0x{:08X} healthBefore={} healthAfter={} observedDelta={} lifeState={}",
                    a_hitID,
                    a_targetForm,
                    *before,
                    *after,
                    *after - *before,
                    lifeState);
            } else {
                logger::info(
                    "[direct-av:{}] RETURN target=0x{:08X} lifeState={}",
                    a_hitID,
                    a_targetForm,
                    lifeState);
            }

            if (after &&
                *after <= 0.0F) {

                const auto protection =
                    ReadProtectionSources(
                        actor);

                logger::info(
                    "[kill-source:{}] target=0x{:08X} health={} lifeState={} runtimeEssential={} runtimeProtected={} baseForm=0x{:08X} baseEssential={} baseProtected={} killBytesEqual={}",
                    a_hitID,
                    a_targetForm,
                    *after,
                    lifeState,
                    protection.runtimeEssential,
                    protection.runtimeProtected,
                    protection.baseForm,
                    protection.baseEssential,
                    protection.baseProtected,
                    g_killImplBytesEqual);
            }

            // One more observation on the next task turn.  This is useful
            // for distinguishing "direct write worked" from
            // "something immediately repaired the value".
            if (g_config.logHealth &&
                g_vanillaGetActorValue) {

                if (auto* tasks =
                        SKSE::GetTaskInterface()) {

                    tasks->AddTask(
                        [
                            a_targetHandle,
                            a_targetForm,
                            a_hitID
                        ]() mutable
                        {
                            auto ref =
                                a_targetHandle.get();

                            if (!ref) {
                                return;
                            }

                            auto* nextActor =
                                ref->As<RE::Actor>();

                            if (!nextActor) {
                                return;
                            }

                            auto* nextAVO =
                                nextActor
                                    ->AsActorValueOwner();

                            if (!nextAVO ||
                                !g_vanillaGetActorValue) {

                                return;
                            }

                            const auto nextHealth =
                                g_vanillaGetActorValue(
                                    nextAVO,
                                    RE::ActorValue::kHealth);

                            const auto nextLife =
                                GetLifeStateRaw(
                                    nextActor);

                            logger::info(
                                "[direct-av:{}] NEXT target=0x{:08X} health={} lifeState={}",
                                a_hitID,
                                a_targetForm,
                                nextHealth,
                                nextLife);

                            if (nextHealth <= 0.0F) {
                                const auto protection =
                                    ReadProtectionSources(
                                        nextActor);

                                logger::info(
                                    "[kill-source:{}] NEXT target=0x{:08X} runtimeEssential={} runtimeProtected={} baseForm=0x{:08X} baseEssential={} baseProtected={} killBytesEqual={}",
                                    a_hitID,
                                    a_targetForm,
                                    protection.runtimeEssential,
                                    protection.runtimeProtected,
                                    protection.baseForm,
                                    protection.baseEssential,
                                    protection.baseProtected,
                                    g_killImplBytesEqual);
                            }
                        });
                }
            }
        }

        std::uint64_t NextHitID()
        {
            static volatile LONG64 sequence = 0;

            return static_cast<std::uint64_t>(
                ::InterlockedIncrement64(
                    &sequence));
        }

        class HitEventSink final :
            public RE::BSTEventSink<
                RE::TESHitEvent>
        {
        public:
            RE::BSEventNotifyControl
            ProcessEvent(
                const RE::TESHitEvent* a_event,
                RE::BSTEventSource<
                    RE::TESHitEvent>*) override
            {
                if (!a_event ||
                    !g_config.playerHasAbsoluteDamage ||
                    !g_bypassReady) {

                    return RE::BSEventNotifyControl::
                        kContinue;
                }

                auto* target =
                    a_event->target.get();

                auto* cause =
                    a_event->cause.get();

                auto* player =
                    RE::PlayerCharacter::
                        GetSingleton();

                if (!target ||
                    !cause ||
                    !player ||
                    cause != player ||
                    target == player) {

                    return RE::BSEventNotifyControl::
                        kContinue;
                }

                const auto targetForm =
                    target->GetFormID();

                if (!ShouldQueueTarget(
                        targetForm)) {

                    return RE::BSEventNotifyControl::
                        kContinue;
                }

                auto* tasks =
                    SKSE::GetTaskInterface();

                if (!tasks) {
                    logger::error(
                        "[direct-av] task interface unavailable");
                    return RE::BSEventNotifyControl::
                        kContinue;
                }

                const auto hitID =
                    NextHitID();

                const auto targetHandle =
                    target->CreateRefHandle();

                const auto sourceForm =
                    a_event->source;

                logger::info(
                    "[direct-av:{}] HIT target=0x{:08X} cause=player source=0x{:08X} eventTid={}",
                    hitID,
                    targetForm,
                    sourceForm,
                    ::GetCurrentThreadId());

                tasks->AddTask(
                    [
                        targetHandle,
                        targetForm,
                        sourceForm,
                        hitID
                    ]() mutable
                    {
                        ApplyDirectDamage(
                            targetHandle,
                            targetForm,
                            sourceForm,
                            hitID);
                    });

                return RE::BSEventNotifyControl::
                    kContinue;
            }
        };

        HitEventSink g_hitSink;

        void RegisterHitEventSink()
        {
            if (g_hitSinkRegistered) {
                return;
            }

            auto* holder =
                RE::ScriptEventSourceHolder::
                    GetSingleton();

            if (!holder) {
                logger::warn(
                    "[direct-av] ScriptEventSourceHolder unavailable");
                return;
            }

            holder->AddEventSink<
                RE::TESHitEvent>(
                    &g_hitSink);

            g_hitSinkRegistered = true;

            logger::info(
                "[direct-av] TESHitEvent sink registered");
        }

        void SetupLog()
        {
            auto path =
                logger::log_directory();

            if (!path) {
                return;
            }

            *path /=
                "UniversalCombatArbiter.log";

            auto sink =
                std::make_shared<
                    spdlog::sinks::
                        basic_file_sink_mt>(
                            path->string(),
                            true);

            auto log =
                std::make_shared<
                    spdlog::logger>(
                        "global",
                        std::move(
                            sink));

            log->set_level(
                spdlog::level::debug);

            log->flush_on(
                spdlog::level::debug);

            spdlog::set_default_logger(
                std::move(log));

            spdlog::set_pattern(
                "[%H:%M:%S.%e] [%l] %v");
        }

        void MessageHandler(
            SKSE::MessagingInterface::
                Message* a_message)
        {
            if (!a_message) {
                return;
            }

            switch (
                a_message->type) {

            case SKSE::MessagingInterface::
                kDataLoaded:

                ResolveBypassFunctions();
                RegisterHitEventSink();
                break;

            case SKSE::MessagingInterface::
                kPostLoadGame:

            case SKSE::MessagingInterface::
                kNewGame:

                ResolveBypassFunctions();
                RegisterHitEventSink();
                break;

            default:
                break;
            }
        }
    }

    bool Initialize(
        const SKSE::LoadInterface* a_skse)
    {
        SetupLog();

        logger::info(
            "UniversalCombatArbiter FINAL Kill-Integrity Probe loading; runtime {}",
            a_skse
                ->RuntimeVersion()
                .string());

        LoadConfig();

        if (!g_pristine.Load()) {
            logger::critical(
                "Failed to read Skyrim executable for pristine vtable recovery; plugin disabled");

            return true;
        }

        auto* messaging =
            SKSE::GetMessagingInterface();

        if (!messaging ||
            !messaging->RegisterListener(
                MessageHandler)) {

            logger::critical(
                "Could not register SKSE message listener");

            return false;
        }

        return true;
    }
}

SKSEPluginLoad(
    const SKSE::LoadInterface* a_skse)
{
    SKSE::Init(a_skse);

    return UCA::Initialize(
        a_skse);
}
