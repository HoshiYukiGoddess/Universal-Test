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

        struct Config
        {
            bool playerHasAbsoluteDamage{ true };
            bool logHealth{ true };
            bool attemptVanillaKillImpl{ true };
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
                "Death-Gate PoC config: player={}, damage={}, cooldown={}ms, logHealth={}, killImpl={}",
                g_config.playerHasAbsoluteDamage,
                g_config.directDamage,
                g_config.cooldownMs,
                g_config.logHealth,
                g_config.attemptVanillaKillImpl);
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

        using KillImpl_t =
            void (*)(
                RE::Actor*,
                RE::Actor*,
                float,
                bool,
                bool);

        GetActorValue_t g_vanillaGetActorValue{};
        ModActorValue_t g_vanillaModActorValue{};
        KillImpl_t g_vanillaKillImpl{};

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

            if (!pristineGet ||
                !pristineMod ||
                (g_config.attemptVanillaKillImpl &&
                 !pristineKillImpl)) {

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

            g_vanillaKillImpl =
                reinterpret_cast<
                    KillImpl_t>(
                        pristineKillImpl);

            g_bypassReady = true;

            logger::info(
                "[direct-av] universal direct-AV bypass ready");

            if (g_config.attemptVanillaKillImpl) {
                logger::info(
                    "[death-gate] pristine KillImpl death transition probe ready");
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

            // Death-gate experiment:
            // For every Actor universally, if Bethesda's pristine AV write
            // has made Health <= 0 but the Actor is still neither dying nor
            // dead, call Bethesda's pristine Actor::KillImpl exactly once.
            //
            // No NPC name, FormID, plugin name or third-party RVA is used.
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

                const auto lifeBeforeKill =
                    GetLifeStateRaw(
                        actor);

                logger::info(
                    "[death-gate:{}] CALL KillImpl target=0x{:08X} health={} lifeBefore={} attacker={} damage={} sendEvent=true ragdollInstant=false",
                    a_hitID,
                    a_targetForm,
                    *after,
                    lifeBeforeKill,
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

                std::optional<float> healthAfterKill;

                if (g_vanillaGetActorValue) {
                    healthAfterKill =
                        g_vanillaGetActorValue(
                            avo,
                            RE::ActorValue::kHealth);
                }

                const auto lifeAfterKill =
                    GetLifeStateRaw(
                        actor);

                if (healthAfterKill) {
                    logger::info(
                        "[death-gate:{}] RETURN KillImpl target=0x{:08X} health={} lifeAfter={} dyingOrDead={}",
                        a_hitID,
                        a_targetForm,
                        *healthAfterKill,
                        lifeAfterKill,
                        IsDyingOrDead(
                            actor));
                } else {
                    logger::info(
                        "[death-gate:{}] RETURN KillImpl target=0x{:08X} lifeAfter={} dyingOrDead={}",
                        a_hitID,
                        a_targetForm,
                        lifeAfterKill,
                        IsDyingOrDead(
                            actor));
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
            "UniversalCombatArbiter FINAL Death-Gate PoC loading; runtime {}",
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