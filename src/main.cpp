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
        constexpr std::size_t kActor_KillDying = 0x0AA;
        constexpr std::size_t kActor_Resurrect = 0x0AB;
        constexpr std::size_t kActor_KillImpl = 0x10E;

        struct Config
        {
            bool playerHasAbsoluteDamage{ true };
            bool logHealth{ true };
            bool attemptVanillaKillImpl{ true };
            bool bypassEssentialGate{ true };
            bool traceLifecycle{ true };
            bool finishDyingStage{ true };
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

            g_config.attemptVanillaKillImpl =
                ReadIniBool(
                    "bAttemptVanillaKillImpl",
                    true);

            g_config.bypassEssentialGate =
                ReadIniBool(
                    "bBypassEssentialGate",
                    true);

            g_config.traceLifecycle =
                ReadIniBool(
                    "bTraceLifecycle",
                    true);

            g_config.finishDyingStage =
                ReadIniBool(
                    "bFinishDyingStage",
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
                "One-Pass Death Bypass config: player={}, damage={}, cooldown={}ms, logHealth={}, killImpl={}, bypassEssential={}, traceLifecycle={}, finishDying={}",
                g_config.playerHasAbsoluteDamage,
                g_config.directDamage,
                g_config.cooldownMs,
                g_config.logHealth,
                g_config.attemptVanillaKillImpl,
                g_config.bypassEssentialGate,
                g_config.traceLifecycle,
                g_config.finishDyingStage);
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

        __declspec(noinline)
        std::string CaptureStackSummary(
            std::size_t a_maxFrames = 14)
        {
            constexpr std::size_t kMaxFrames = 20;

            std::array<void*, kMaxFrames> frames{};

            const auto requested =
                static_cast<ULONG>(
                    std::min<std::size_t>(
                        a_maxFrames,
                        kMaxFrames));

            // Skip CaptureStackSummary itself.  Keeping the immediate
            // event/wrapper frame is useful because the next frames show
            // exactly who entered that lifecycle callback.
            const auto captured =
                ::CaptureStackBackTrace(
                    1,
                    requested,
                    frames.data(),
                    nullptr);

            if (captured == 0) {
                return "<unavailable>";
            }

            std::string out;

            for (USHORT i = 0;
                 i < captured;
                 ++i) {

                if (i != 0) {
                    out += " <- ";
                }

                out += FormatAddress(
                    reinterpret_cast<
                        std::uintptr_t>(
                            frames[i]));
            }

            return out;
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

        using KillDying_t =
            void (*)(
                RE::Actor*);

        using Resurrect_t =
            void (*)(
                RE::Actor*,
                bool,
                bool);

        using KillImpl_t =
            void (*)(
                RE::Actor*,
                RE::Actor*,
                float,
                bool,
                bool);

        GetActorValue_t g_vanillaGetActorValue{};
        ModActorValue_t g_vanillaModActorValue{};
        KillDying_t g_vanillaKillDying{};
        Resurrect_t g_pristineResurrect{};
        KillImpl_t g_vanillaKillImpl{};

        KillDying_t g_prevKillDying{};
        Resurrect_t g_prevResurrect{};

        volatile LONG64 g_killDyingVCalls = 0;
        volatile LONG64 g_resurrectVCalls = 0;
        volatile LONG64 g_deathEvents = 0;
        volatile LONG64 g_bleedoutEvents = 0;

        bool g_lifecycleHooksInstalled{ false };
        bool g_lifecycleEventSinksRegistered{ false };

        bool g_bypassReady{ false };
        bool g_hitSinkRegistered{ false };

        std::mutex g_hitMutex;
        std::unordered_map<
            RE::FormID,
            ULONGLONG> g_lastHitByTarget;

        std::unordered_map<
            RE::FormID,
            bool> g_killAttemptedByTarget;

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

        bool IsDyingOrDead(
            RE::Actor* a_actor)
        {
            if (!a_actor) {
                return true;
            }

            auto* state =
                a_actor->AsActorState();

            if (!state) {
                return false;
            }

            const auto life =
                state->GetLifeState();

            return life ==
                       RE::ACTOR_LIFE_STATE::kDying ||
                   life ==
                       RE::ACTOR_LIFE_STATE::kDead;
        }

        struct ProtectionSnapshot
        {
            bool runtimeEssential{};
            bool runtimeProtected{};
            bool baseEssential{};
            bool baseProtected{};
            RE::FormID baseForm{};
        };

        ProtectionSnapshot ReadProtection(
            RE::Actor* a_actor)
        {
            ProtectionSnapshot result{};

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

        void ClearDeathProtection(
            RE::Actor* a_actor)
        {
            if (!a_actor) {
                return;
            }

            auto& runtime =
                a_actor->GetActorRuntimeData();

            runtime.boolFlags.reset(
                RE::Actor::BOOL_FLAGS::kEssential);

            runtime.boolFlags.reset(
                RE::Actor::BOOL_FLAGS::kProtected);

            if (auto* base =
                    a_actor->GetActorBase()) {

                base->actorData.actorBaseFlags.reset(
                    RE::ACTOR_BASE_DATA::Flag::
                        kEssential);

                base->actorData.actorBaseFlags.reset(
                    RE::ACTOR_BASE_DATA::Flag::
                        kProtected);
            }
        }

        void RestoreDeathProtection(
            RE::Actor* a_actor,
            const ProtectionSnapshot& a_snapshot)
        {
            if (!a_actor) {
                return;
            }

            auto& runtime =
                a_actor->GetActorRuntimeData();

            if (a_snapshot.runtimeEssential) {
                runtime.boolFlags.set(
                    RE::Actor::BOOL_FLAGS::kEssential);
            } else {
                runtime.boolFlags.reset(
                    RE::Actor::BOOL_FLAGS::kEssential);
            }

            if (a_snapshot.runtimeProtected) {
                runtime.boolFlags.set(
                    RE::Actor::BOOL_FLAGS::kProtected);
            } else {
                runtime.boolFlags.reset(
                    RE::Actor::BOOL_FLAGS::kProtected);
            }

            if (auto* base =
                    a_actor->GetActorBase()) {

                if (a_snapshot.baseEssential) {
                    base->actorData.actorBaseFlags.set(
                        RE::ACTOR_BASE_DATA::Flag::
                            kEssential);
                } else {
                    base->actorData.actorBaseFlags.reset(
                        RE::ACTOR_BASE_DATA::Flag::
                            kEssential);
                }

                if (a_snapshot.baseProtected) {
                    base->actorData.actorBaseFlags.set(
                        RE::ACTOR_BASE_DATA::Flag::
                            kProtected);
                } else {
                    base->actorData.actorBaseFlags.reset(
                        RE::ACTOR_BASE_DATA::Flag::
                            kProtected);
                }
            }
        }

        template <class Fn>
        Fn WriteVFuncRaw(
            std::uintptr_t a_vtable,
            std::size_t a_slot,
            Fn a_hook)
        {
            if (!a_vtable ||
                !a_hook) {
                return nullptr;
            }

            auto* entry =
                reinterpret_cast<std::uintptr_t*>(
                    a_vtable +
                    a_slot * sizeof(void*));

            DWORD oldProtect = 0;

            if (!::VirtualProtect(
                    entry,
                    sizeof(*entry),
                    PAGE_EXECUTE_READWRITE,
                    &oldProtect)) {

                logger::error(
                    "[lifecycle] VirtualProtect failed for vtable=0x{:X}[0x{:X}]",
                    a_vtable,
                    a_slot);

                return nullptr;
            }

            const auto previous =
                *entry;

            *entry =
                reinterpret_cast<
                    std::uintptr_t>(
                        a_hook);

            DWORD ignored = 0;

            ::VirtualProtect(
                entry,
                sizeof(*entry),
                oldProtect,
                &ignored);

            return reinterpret_cast<Fn>(
                previous);
        }

        bool MarkKillAttemptOnce(
            RE::FormID a_formID)
        {
            std::scoped_lock lock{
                g_hitMutex
            };

            const auto [it, inserted] =
                g_killAttemptedByTarget.emplace(
                    a_formID,
                    true);

            return inserted;
        }

        void V_KillDying(
            RE::Actor* a_self)
        {
            const auto callNo =
                static_cast<std::uint64_t>(
                    ::InterlockedIncrement64(
                        &g_killDyingVCalls));

            const auto beforeLife =
                GetLifeStateRaw(
                    a_self);

            const auto beforeProtection =
                ReadProtection(
                    a_self);

            logger::info(
                "[lifecycle-vcall:{}] KillDying ENTER self=0x{:08X} lifeState={} runtimeE={} runtimeP={} baseE={} baseP={} caller={}",
                callNo,
                a_self ?
                    a_self->GetFormID() :
                    0,
                beforeLife,
                beforeProtection.runtimeEssential,
                beforeProtection.runtimeProtected,
                beforeProtection.baseEssential,
                beforeProtection.baseProtected,
                FormatAddress(
                    reinterpret_cast<std::uintptr_t>(
                        _ReturnAddress())));

            logger::info(
                "[lifecycle-stack:{}] KillDying {}",
                callNo,
                CaptureStackSummary());

            if (g_prevKillDying) {
                g_prevKillDying(
                    a_self);
            }

            const auto afterProtection =
                ReadProtection(
                    a_self);

            logger::info(
                "[lifecycle-vcall:{}] KillDying RETURN self=0x{:08X} lifeState={} runtimeE={} runtimeP={} baseE={} baseP={}",
                callNo,
                a_self ?
                    a_self->GetFormID() :
                    0,
                GetLifeStateRaw(
                    a_self),
                afterProtection.runtimeEssential,
                afterProtection.runtimeProtected,
                afterProtection.baseEssential,
                afterProtection.baseProtected);
        }

        void V_Resurrect(
            RE::Actor* a_self,
            bool a_resetInventory,
            bool a_attach3D)
        {
            const auto callNo =
                static_cast<std::uint64_t>(
                    ::InterlockedIncrement64(
                        &g_resurrectVCalls));

            logger::info(
                "[lifecycle-vcall:{}] Resurrect ENTER self=0x{:08X} lifeState={} resetInventory={} attach3D={} caller={}",
                callNo,
                a_self ?
                    a_self->GetFormID() :
                    0,
                GetLifeStateRaw(
                    a_self),
                a_resetInventory,
                a_attach3D,
                FormatAddress(
                    reinterpret_cast<std::uintptr_t>(
                        _ReturnAddress())));

            logger::info(
                "[lifecycle-stack:{}] Resurrect {}",
                callNo,
                CaptureStackSummary());

            if (g_prevResurrect) {
                g_prevResurrect(
                    a_self,
                    a_resetInventory,
                    a_attach3D);
            }

            logger::info(
                "[lifecycle-vcall:{}] Resurrect RETURN self=0x{:08X} lifeState={}",
                callNo,
                a_self ?
                    a_self->GetFormID() :
                    0,
                GetLifeStateRaw(
                    a_self));
        }

        class DeathEventSink final :
            public RE::BSTEventSink<
                RE::TESDeathEvent>
        {
        public:
            RE::BSEventNotifyControl
            ProcessEvent(
                const RE::TESDeathEvent* a_event,
                RE::BSTEventSource<
                    RE::TESDeathEvent>*) override
            {
                if (!a_event) {
                    return RE::BSEventNotifyControl::
                        kContinue;
                }

                const auto eventNo =
                    static_cast<std::uint64_t>(
                        ::InterlockedIncrement64(
                            &g_deathEvents));

                auto dying =
                    a_event->actorDying.get();

                auto killer =
                    a_event->actorKiller.get();

                auto* dyingActor =
                    dying ?
                        dying->As<RE::Actor>() :
                        nullptr;

                const auto protection =
                    ReadProtection(
                        dyingActor);

                logger::info(
                    "[death-event:{}] dying=0x{:08X} killer=0x{:08X} dead={} lifeState={} runtimeE={} runtimeP={} baseE={} baseP={} tid={}",
                    eventNo,
                    dying ?
                        dying->GetFormID() :
                        0,
                    killer ?
                        killer->GetFormID() :
                        0,
                    a_event->dead,
                    GetLifeStateRaw(
                        dyingActor),
                    protection.runtimeEssential,
                    protection.runtimeProtected,
                    protection.baseEssential,
                    protection.baseProtected,
                    ::GetCurrentThreadId());

                logger::info(
                    "[death-stack:{}] {}",
                    eventNo,
                    CaptureStackSummary());

                return RE::BSEventNotifyControl::
                    kContinue;
            }
        };

        class BleedoutEventSink final :
            public RE::BSTEventSink<
                RE::TESEnterBleedoutEvent>
        {
        public:
            RE::BSEventNotifyControl
            ProcessEvent(
                const RE::TESEnterBleedoutEvent* a_event,
                RE::BSTEventSource<
                    RE::TESEnterBleedoutEvent>*) override
            {
                if (!a_event) {
                    return RE::BSEventNotifyControl::
                        kContinue;
                }

                const auto eventNo =
                    static_cast<std::uint64_t>(
                        ::InterlockedIncrement64(
                            &g_bleedoutEvents));

                auto actorRef =
                    a_event->actor.get();

                auto* actor =
                    actorRef ?
                        actorRef->As<RE::Actor>() :
                        nullptr;

                const auto protection =
                    ReadProtection(
                        actor);

                logger::info(
                    "[bleedout-event:{}] actor=0x{:08X} lifeState={} runtimeE={} runtimeP={} baseE={} baseP={} tid={}",
                    eventNo,
                    actorRef ?
                        actorRef->GetFormID() :
                        0,
                    GetLifeStateRaw(
                        actor),
                    protection.runtimeEssential,
                    protection.runtimeProtected,
                    protection.baseEssential,
                    protection.baseProtected,
                    ::GetCurrentThreadId());

                logger::info(
                    "[bleedout-stack:{}] {}",
                    eventNo,
                    CaptureStackSummary());

                return RE::BSEventNotifyControl::
                    kContinue;
            }
        };

        DeathEventSink g_deathSink;
        BleedoutEventSink g_bleedoutSink;

        void RegisterLifecycleEventSinks()
        {
            if (g_lifecycleEventSinksRegistered ||
                !g_config.traceLifecycle) {
                return;
            }

            auto* holder =
                RE::ScriptEventSourceHolder::
                    GetSingleton();

            if (!holder) {
                logger::warn(
                    "[lifecycle] ScriptEventSourceHolder unavailable");
                return;
            }

            holder->AddEventSink<
                RE::TESDeathEvent>(
                    &g_deathSink);

            holder->AddEventSink<
                RE::TESEnterBleedoutEvent>(
                    &g_bleedoutSink);

            g_lifecycleEventSinksRegistered =
                true;

            logger::info(
                "[lifecycle] TESDeathEvent + TESEnterBleedoutEvent sinks registered");
        }

        void InstallLifecycleVTableHooks(
            std::uintptr_t a_actorVT)
        {
            if (g_lifecycleHooksInstalled ||
                !g_config.traceLifecycle ||
                !a_actorVT) {
                return;
            }

            const auto currentKillDying =
                *reinterpret_cast<
                    const std::uintptr_t*>(
                        a_actorVT +
                        kActor_KillDying *
                            sizeof(void*));

            const auto currentResurrect =
                *reinterpret_cast<
                    const std::uintptr_t*>(
                        a_actorVT +
                        kActor_Resurrect *
                            sizeof(void*));

            g_prevKillDying =
                WriteVFuncRaw(
                    a_actorVT,
                    kActor_KillDying,
                    V_KillDying);

            g_prevResurrect =
                WriteVFuncRaw(
                    a_actorVT,
                    kActor_Resurrect,
                    V_Resurrect);

            logger::info(
                "[lifecycle] KillDying vtable current={} ours={}",
                FormatAddress(
                    currentKillDying),
                FormatAddress(
                    reinterpret_cast<std::uintptr_t>(
                        V_KillDying)));

            logger::info(
                "[lifecycle] Resurrect vtable current={} ours={}",
                FormatAddress(
                    currentResurrect),
                FormatAddress(
                    reinterpret_cast<std::uintptr_t>(
                        V_Resurrect)));

            g_lifecycleHooksInstalled =
                g_prevKillDying != nullptr &&
                g_prevResurrect != nullptr;
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

            static REL::Relocation<
                std::uintptr_t>
                actorVTable{
                    RE::VTABLE_Actor[0]
                };

            const auto actorVT =
                actorVTable.address();

            const auto currentKillImpl =
                *reinterpret_cast<
                    const std::uintptr_t*>(
                        actorVT +
                        kActor_KillImpl *
                            sizeof(void*));

            const auto pristineKillImpl =
                g_pristine.ResolveVFunc(
                    actorVT,
                    kActor_KillImpl);

            const auto pristineKillDying =
                g_pristine.ResolveVFunc(
                    actorVT,
                    kActor_KillDying);

            const auto pristineResurrect =
                g_pristine.ResolveVFunc(
                    actorVT,
                    kActor_Resurrect);

            InstallLifecycleVTableHooks(
                actorVT);

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

            logger::info(
                "[death-gate] Actor vtable=0x{:X}; current KillImpl={}; pristine KillImpl={}; same={}",
                actorVT,
                FormatAddress(
                    currentKillImpl),
                pristineKillImpl ?
                    FormatAddress(
                        pristineKillImpl) :
                    std::string{
                        "<unavailable>"
                    },
                pristineKillImpl != 0 &&
                    currentKillImpl ==
                        pristineKillImpl);

            logger::info(
                "[lifecycle] pristine KillDying={} pristine Resurrect={}",
                pristineKillDying ?
                    FormatAddress(
                        pristineKillDying) :
                    std::string{
                        "<unavailable>"
                    },
                pristineResurrect ?
                    FormatAddress(
                        pristineResurrect) :
                    std::string{
                        "<unavailable>"
                    });

            if (!pristineGet ||
                !pristineMod ||
                (g_config.attemptVanillaKillImpl &&
                 !pristineKillImpl) ||
                (g_config.finishDyingStage &&
                 !pristineKillDying)) {

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

            g_vanillaKillDying =
                reinterpret_cast<
                    KillDying_t>(
                        pristineKillDying);

            g_pristineResurrect =
                reinterpret_cast<
                    Resurrect_t>(
                        pristineResurrect);

            g_vanillaKillImpl =
                reinterpret_cast<
                    KillImpl_t>(
                        pristineKillImpl);

            g_bypassReady = true;

            logger::info(
                "[direct-av] universal direct-AV bypass ready");

            if (g_config.attemptVanillaKillImpl) {
                logger::info(
                    "[essential-gate] pristine KillImpl death transition probe ready");
            }

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

            if (g_vanillaGetActorValue) {
                after =
                    g_vanillaGetActorValue(
                        avo,
                        RE::ActorValue::kHealth);
            }

            const auto lifeAfterAV =
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
                    lifeAfterAV);
            } else {
                logger::info(
                    "[direct-av:{}] RETURN target=0x{:08X} lifeState={}",
                    a_hitID,
                    a_targetForm,
                    lifeAfterAV);
            }

            // One-pass death bypass + second-layer diagnosis:
            //
            // Stage A: snapshot both Actor runtime and TESNPC base
            // Essential/Protected flags.
            // Stage B: clear both layers and call pristine KillImpl.
            // Stage C: if KillImpl reaches kDying but has not completed,
            // call pristine KillDying once.
            // Stage D: if still not Dying/Dead, report whether virtual
            // KillDying/Resurrect calls, DeathEvent, or BleedoutEvent fired.
            //
            // No NPC name, FormID, third-party module name, or third-party
            // RVA is used for behavior decisions.
            if (g_config.attemptVanillaKillImpl &&
                g_vanillaKillImpl &&
                after &&
                *after <= 0.0F &&
                !IsDyingOrDead(actor) &&
                MarkKillAttemptOnce(
                    a_targetForm)) {

                auto* player =
                    RE::PlayerCharacter::
                        GetSingleton();

                const auto snapshot =
                    ReadProtection(
                        actor);

                const auto lifeBefore =
                    GetLifeStateRaw(
                        actor);

                const auto killDyingBefore =
                    ::InterlockedCompareExchange64(
                        &g_killDyingVCalls,
                        0,
                        0);

                const auto resurrectBefore =
                    ::InterlockedCompareExchange64(
                        &g_resurrectVCalls,
                        0,
                        0);

                const auto deathEventsBefore =
                    ::InterlockedCompareExchange64(
                        &g_deathEvents,
                        0,
                        0);

                const auto bleedoutBefore =
                    ::InterlockedCompareExchange64(
                        &g_bleedoutEvents,
                        0,
                        0);

                logger::info(
                    "[one-pass:{}] BEFORE target=0x{:08X} health={} lifeState={} runtimeE={} runtimeP={} baseForm=0x{:08X} baseE={} baseP={}",
                    a_hitID,
                    a_targetForm,
                    *after,
                    lifeBefore,
                    snapshot.runtimeEssential,
                    snapshot.runtimeProtected,
                    snapshot.baseForm,
                    snapshot.baseEssential,
                    snapshot.baseProtected);

                if (g_config.bypassEssentialGate) {
                    ClearDeathProtection(
                        actor);
                }

                const auto atCall =
                    ReadProtection(
                        actor);

                logger::info(
                    "[one-pass:{}] FLAGS-CLEARED runtimeE={} runtimeP={} baseE={} baseP={}",
                    a_hitID,
                    atCall.runtimeEssential,
                    atCall.runtimeProtected,
                    atCall.baseEssential,
                    atCall.baseProtected);

                logger::info(
                    "[one-pass:{}] CALL KillImpl attacker={} damage={} sendEvent=true ragdollInstant=false",
                    a_hitID,
                    player ?
                        "player" :
                        "null",
                    amount);

                g_vanillaKillImpl(
                    actor,
                    player,
                    amount,
                    true,
                    false);

                auto healthAfterKill =
                    g_vanillaGetActorValue ?
                        std::optional<float>{
                            g_vanillaGetActorValue(
                                avo,
                                RE::ActorValue::kHealth)
                        } :
                        std::nullopt;

                auto lifeAfterKill =
                    GetLifeStateRaw(
                        actor);

                auto afterKillProtection =
                    ReadProtection(
                        actor);

                logger::info(
                    "[one-pass:{}] RETURN KillImpl health={} lifeState={} dyingOrDead={} runtimeE={} runtimeP={} baseE={} baseP={}",
                    a_hitID,
                    healthAfterKill ?
                        *healthAfterKill :
                        0.0F,
                    lifeAfterKill,
                    IsDyingOrDead(
                        actor),
                    afterKillProtection.runtimeEssential,
                    afterKillProtection.runtimeProtected,
                    afterKillProtection.baseEssential,
                    afterKillProtection.baseProtected);

                // If KillImpl actually reached the normal kDying stage but
                // did not finish, advance only the documented next virtual
                // stage.  We do NOT force lifeState to kDying ourselves.
                if (g_config.finishDyingStage &&
                    g_vanillaKillDying &&
                    lifeAfterKill ==
                        static_cast<std::uint32_t>(
                            RE::ACTOR_LIFE_STATE::
                                kDying)) {

                    logger::info(
                        "[one-pass:{}] CALL pristine KillDying because lifeState==kDying",
                        a_hitID);

                    g_vanillaKillDying(
                        actor);

                    logger::info(
                        "[one-pass:{}] RETURN pristine KillDying lifeState={} dyingOrDead={}",
                        a_hitID,
                        GetLifeStateRaw(
                            actor),
                        IsDyingOrDead(
                            actor));
                }

                const auto lifeFinal =
                    GetLifeStateRaw(
                        actor);

                const auto finalProtection =
                    ReadProtection(
                        actor);

                const auto killDyingAfter =
                    ::InterlockedCompareExchange64(
                        &g_killDyingVCalls,
                        0,
                        0);

                const auto resurrectAfter =
                    ::InterlockedCompareExchange64(
                        &g_resurrectVCalls,
                        0,
                        0);

                const auto deathEventsAfter =
                    ::InterlockedCompareExchange64(
                        &g_deathEvents,
                        0,
                        0);

                const auto bleedoutAfter =
                    ::InterlockedCompareExchange64(
                        &g_bleedoutEvents,
                        0,
                        0);

                logger::info(
                    "[second-layer:{}] FINAL lifeState={} dyingOrDead={} runtimeE={} runtimeP={} baseE={} baseP={} killDyingVCallsDelta={} resurrectVCallsDelta={} deathEventsDelta={} bleedoutEventsDelta={}",
                    a_hitID,
                    lifeFinal,
                    IsDyingOrDead(
                        actor),
                    finalProtection.runtimeEssential,
                    finalProtection.runtimeProtected,
                    finalProtection.baseEssential,
                    finalProtection.baseProtected,
                    killDyingAfter -
                        killDyingBefore,
                    resurrectAfter -
                        resurrectBefore,
                    deathEventsAfter -
                        deathEventsBefore,
                    bleedoutAfter -
                        bleedoutBefore);

                // If no real Dying/Dead transition occurred, restore both
                // base and runtime protection layers.  If death did start,
                // keep them cleared for this test session so the engine
                // cannot immediately re-establish the same vanilla gate.
                if (g_config.bypassEssentialGate &&
                    !IsDyingOrDead(
                        actor)) {

                    RestoreDeathProtection(
                        actor,
                        snapshot);

                    const auto restored =
                        ReadProtection(
                            actor);

                    logger::info(
                        "[one-pass:{}] RESTORE runtimeE={} runtimeP={} baseE={} baseP={}",
                        a_hitID,
                        restored.runtimeEssential,
                        restored.runtimeProtected,
                        restored.baseEssential,
                        restored.baseProtected);
                } else if (IsDyingOrDead(
                               actor)) {

                    logger::info(
                        "[one-pass:{}] death transition accepted; protection flags remain cleared for this test session",
                        a_hitID);
                }
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

                            logger::info(
                                "[direct-av:{}] NEXT target=0x{:08X} health={} lifeState={} dyingOrDead={}",
                                a_hitID,
                                a_targetForm,
                                nextHealth,
                                GetLifeStateRaw(
                                    nextActor),
                                IsDyingOrDead(
                                    nextActor));
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
                RegisterLifecycleEventSinks();
                break;

            case SKSE::MessagingInterface::
                kPostLoadGame:

            case SKSE::MessagingInterface::
                kNewGame:

                ResolveBypassFunctions();
                RegisterHitEventSink();
                RegisterLifecycleEventSinks();
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
            "UniversalCombatArbiter FINAL Stop-Line Death Diagnostic loading; runtime {}",
            a_skse
                ->RuntimeVersion()
                .string());

        LoadConfig();

        logger::info(
            "[stop-line] Final diagnostic build: synchronous lifecycle stacks enabled");

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
