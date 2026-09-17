#include "PCH.h"

namespace logger = SKSE::log;
using namespace std::literals;

namespace UCA
{
    namespace
    {
        constexpr std::size_t kActor_KillDying = 0x0AA;
        constexpr std::size_t kActor_Resurrect = 0x0AB;
        constexpr std::size_t kActor_HandleHealthDamage = 0x104;
        constexpr std::size_t kActor_KillImpl = 0x10E;
        constexpr std::size_t kActor_CheckClampDamageModifier = 0x127;

        constexpr std::size_t kAVO_SetBaseActorValue = 0x04;
        constexpr std::size_t kAVO_ModBaseActorValue = 0x05;
        constexpr std::size_t kAVO_ModActorValue = 0x06;
        constexpr std::size_t kAVO_SetActorValue = 0x07;

        struct Config
        {
            bool playerHasAbsoluteDamage{ true };
            bool terminalDeath{ true };
            float terminalHoldSeconds{ 10.0F };
            std::string attackerPlugin{};
            std::uint32_t attackerLocalFormID{ 0 };
            RE::TESNPC* attackerBase{ nullptr };
        };

        Config g_config;

        std::filesystem::path GetIniPath()
        {
            return std::filesystem::path{ "Data" } / "SKSE" / "Plugins" / "UniversalCombatArbiter.ini";
        }

        std::string ReadIniString(const char* a_key, const char* a_default = "")
        {
            std::array<char, 512> buffer{};
            const auto path = GetIniPath().string();
            ::GetPrivateProfileStringA("General", a_key, a_default, buffer.data(), static_cast<DWORD>(buffer.size()), path.c_str());
            return buffer.data();
        }

        bool ReadIniBool(const char* a_key, bool a_default)
        {
            const auto raw = ReadIniString(a_key, a_default ? "1" : "0");
            return raw == "1" || raw == "true" || raw == "TRUE" || raw == "yes" || raw == "YES";
        }

        float ReadIniFloat(const char* a_key, float a_default)
        {
            const auto raw = ReadIniString(a_key, "");
            if (raw.empty()) {
                return a_default;
            }
            try {
                return std::stof(raw);
            } catch (...) {
                return a_default;
            }
        }

        std::uint32_t ReadIniUInt(const char* a_key, std::uint32_t a_default)
        {
            const auto raw = ReadIniString(a_key, "");
            if (raw.empty()) {
                return a_default;
            }
            try {
                std::size_t parsed = 0;
                const auto value = std::stoul(raw, &parsed, 0);
                return parsed ? static_cast<std::uint32_t>(value) : a_default;
            } catch (...) {
                return a_default;
            }
        }

        void LoadConfig()
        {
            g_config.playerHasAbsoluteDamage = ReadIniBool("bPlayerHasAbsoluteDamage", true);
            g_config.terminalDeath = ReadIniBool("bTerminalDeath", true);
            g_config.terminalHoldSeconds = std::max(0.0F, ReadIniFloat("fTerminalHoldSeconds", 10.0F));
            g_config.attackerPlugin = ReadIniString("sAttackerPlugin", "");
            g_config.attackerLocalFormID = ReadIniUInt("iAttackerLocalFormID", 0);

            logger::info("Config: player={}, terminal={}, hold={}s, attackerPlugin='{}', localFormID=0x{:X}",
                g_config.playerHasAbsoluteDamage,
                g_config.terminalDeath,
                g_config.terminalHoldSeconds,
                g_config.attackerPlugin,
                g_config.attackerLocalFormID);
        }

        void ResolveConfiguredAttacker()
        {
            g_config.attackerBase = nullptr;
            if (g_config.attackerPlugin.empty() || g_config.attackerLocalFormID == 0) {
                return;
            }

            if (auto* data = RE::TESDataHandler::GetSingleton()) {
                g_config.attackerBase = data->LookupForm<RE::TESNPC>(g_config.attackerLocalFormID, g_config.attackerPlugin);
            }

            if (g_config.attackerBase) {
                logger::info("Configured attacker resolved: {} (0x{:08X})",
                    g_config.attackerBase->GetName(),
                    g_config.attackerBase->GetFormID());
            } else {
                logger::warn("Configured attacker could not be resolved");
            }
        }

        bool IsAbsoluteAttacker(RE::Actor* a_attacker)
        {
            if (!a_attacker) {
                return false;
            }
            if (g_config.playerHasAbsoluteDamage && a_attacker->IsPlayerRef()) {
                return true;
            }
            return g_config.attackerBase && a_attacker->GetActorBase() == g_config.attackerBase;
        }

        class PristineImage
        {
        public:
            bool Load()
            {
                const auto module = ::GetModuleHandleW(nullptr);
                if (!module) {
                    logger::error("GetModuleHandleW(nullptr) failed");
                    return false;
                }
                _runtimeBase = reinterpret_cast<std::uintptr_t>(module);

                std::array<wchar_t, 32768> path{};
                const auto count = ::GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
                if (count == 0 || count >= path.size()) {
                    logger::error("GetModuleFileNameW failed");
                    return false;
                }

                std::ifstream input(std::filesystem::path{ path.data() }, std::ios::binary | std::ios::ate);
                if (!input) {
                    logger::error("Could not open Skyrim executable on disk");
                    return false;
                }
                const auto size = input.tellg();
                if (size <= 0) {
                    return false;
                }
                _bytes.resize(static_cast<std::size_t>(size));
                input.seekg(0, std::ios::beg);
                input.read(reinterpret_cast<char*>(_bytes.data()), static_cast<std::streamsize>(size));
                if (!input) {
                    logger::error("Could not read Skyrim executable");
                    return false;
                }

                if (_bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
                    return false;
                }
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(_bytes.data());
                if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
                    return false;
                }
                if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > _bytes.size()) {
                    return false;
                }

                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(_bytes.data() + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                    return false;
                }

                _preferredBase = static_cast<std::uintptr_t>(nt->OptionalHeader.ImageBase);
                _sizeOfImage = nt->OptionalHeader.SizeOfImage;
                _sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;

                const auto* first = IMAGE_FIRST_SECTION(nt);
                _sections.assign(first, first + nt->FileHeader.NumberOfSections);

                logger::info("Pristine executable loaded: runtimeBase=0x{:X}, preferredBase=0x{:X}, imageSize=0x{:X}",
                    _runtimeBase, _preferredBase, _sizeOfImage);
                return true;
            }

            [[nodiscard]] std::uintptr_t ResolveVFunc(std::uintptr_t a_runtimeVTable, std::size_t a_slot) const
            {
                if (!_runtimeBase || _bytes.empty() || a_runtimeVTable < _runtimeBase) {
                    return 0;
                }

                const auto vtableRva = a_runtimeVTable - _runtimeBase;
                const auto entryRva = vtableRva + (a_slot * sizeof(std::uintptr_t));
                const auto fileOffset = RvaToFileOffset(entryRva);
                if (!fileOffset || *fileOffset + sizeof(std::uint64_t) > _bytes.size()) {
                    return 0;
                }

                std::uint64_t preferredVA = 0;
                std::memcpy(&preferredVA, _bytes.data() + *fileOffset, sizeof(preferredVA));
                if (preferredVA < _preferredBase || preferredVA >= (_preferredBase + _sizeOfImage)) {
                    return 0;
                }

                return _runtimeBase + static_cast<std::uintptr_t>(preferredVA - _preferredBase);
            }

        private:
            [[nodiscard]] std::optional<std::size_t> RvaToFileOffset(std::uintptr_t a_rva) const
            {
                if (a_rva < _sizeOfHeaders) {
                    return static_cast<std::size_t>(a_rva);
                }
                for (const auto& section : _sections) {
                    const auto begin = static_cast<std::uintptr_t>(section.VirtualAddress);
                    const auto span = static_cast<std::uintptr_t>(std::max(section.Misc.VirtualSize, section.SizeOfRawData));
                    if (a_rva >= begin && a_rva < begin + span) {
                        const auto delta = a_rva - begin;
                        if (delta >= section.SizeOfRawData) {
                            return std::nullopt;
                        }
                        return static_cast<std::size_t>(section.PointerToRawData + delta);
                    }
                }
                return std::nullopt;
            }

            std::vector<std::byte> _bytes{};
            std::vector<IMAGE_SECTION_HEADER> _sections{};
            std::uintptr_t _runtimeBase{ 0 };
            std::uintptr_t _preferredBase{ 0 };
            std::uintptr_t _sizeOfImage{ 0 };
            std::uintptr_t _sizeOfHeaders{ 0 };
        };

        PristineImage g_pristine;

        using HandleHealthDamage_t = void (*)(RE::Actor*, RE::Actor*, float);
        using KillImpl_t = void (*)(RE::Actor*, RE::Actor*, float, bool, bool);
        using CheckClampDamageModifier_t = float (*)(RE::Actor*, RE::ActorValue, float);
        using KillDying_t = void (*)(RE::Actor*);
        using Resurrect_t = void (*)(RE::Actor*, bool, bool);

        using SetBaseActorValue_t = void (*)(RE::ActorValueOwner*, RE::ActorValue, float);
        using ModBaseActorValue_t = void (*)(RE::ActorValueOwner*, RE::ActorValue, float);
        using ModActorValue_t = void (*)(RE::ActorValueOwner*, RE::ACTOR_VALUE_MODIFIER, RE::ActorValue, float);
        using SetActorValue_t = void (*)(RE::ActorValueOwner*, RE::ActorValue, float);

        struct FunctionSet
        {
            HandleHealthDamage_t prevHandleHealth{};
            HandleHealthDamage_t vanillaHandleHealth{};
            KillImpl_t prevKillImpl{};
            KillImpl_t vanillaKillImpl{};
            CheckClampDamageModifier_t prevCheckClamp{};
            CheckClampDamageModifier_t vanillaCheckClamp{};
            KillDying_t prevKillDying{};
            KillDying_t vanillaKillDying{};
            Resurrect_t prevResurrect{};
            Resurrect_t vanillaResurrect{};

            SetBaseActorValue_t prevSetBase{};
            SetBaseActorValue_t vanillaSetBase{};
            ModBaseActorValue_t prevModBase{};
            ModBaseActorValue_t vanillaModBase{};
            ModActorValue_t prevModAV{};
            ModActorValue_t vanillaModAV{};
            SetActorValue_t prevSetAV{};
            SetActorValue_t vanillaSetAV{};
        };

        FunctionSet g_fn;

        struct AbsoluteContext
        {
            RE::Actor* target{};
            RE::ActorValueOwner* targetAVO{};
            std::uint32_t depth{};
        };

        thread_local AbsoluteContext g_ctx{};

        class ScopedAbsoluteContext
        {
        public:
            explicit ScopedAbsoluteContext(RE::Actor* a_target)
            {
                if (g_ctx.depth++ == 0) {
                    g_ctx.target = a_target;
                    g_ctx.targetAVO = a_target ? a_target->AsActorValueOwner() : nullptr;
                    _owner = true;
                }
            }

            ~ScopedAbsoluteContext()
            {
                if (g_ctx.depth > 0 && --g_ctx.depth == 0) {
                    g_ctx.target = nullptr;
                    g_ctx.targetAVO = nullptr;
                }
            }

            ScopedAbsoluteContext(const ScopedAbsoluteContext&) = delete;
            ScopedAbsoluteContext& operator=(const ScopedAbsoluteContext&) = delete;

        private:
            bool _owner{ false };
        };

        struct TerminalEntry
        {
            RE::ActorValueOwner* avo{};
            std::chrono::steady_clock::time_point until{};
        };

        std::mutex g_terminalLock;
        std::unordered_map<RE::Actor*, TerminalEntry> g_terminalActors;
        std::unordered_map<RE::ActorValueOwner*, std::chrono::steady_clock::time_point> g_terminalAVOs;

        bool IsExpired(const std::chrono::steady_clock::time_point& a_until)
        {
            return std::chrono::steady_clock::now() >= a_until;
        }

        void MarkTerminal(RE::Actor* a_actor)
        {
            if (!g_config.terminalDeath || !a_actor || g_config.terminalHoldSeconds <= 0.0F) {
                return;
            }
            const auto millis = static_cast<std::int64_t>(g_config.terminalHoldSeconds * 1000.0F);
            const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
            auto* avo = a_actor->AsActorValueOwner();

            std::scoped_lock lock(g_terminalLock);
            g_terminalActors[a_actor] = TerminalEntry{ avo, until };
            if (avo) {
                g_terminalAVOs[avo] = until;
            }
            logger::info("Terminal mark applied to 0x{:08X} for {}s", a_actor->GetFormID(), g_config.terminalHoldSeconds);
        }

        bool IsTerminal(RE::Actor* a_actor)
        {
            if (!a_actor) {
                return false;
            }
            std::scoped_lock lock(g_terminalLock);
            const auto it = g_terminalActors.find(a_actor);
            if (it == g_terminalActors.end()) {
                return false;
            }
            if (IsExpired(it->second.until)) {
                if (it->second.avo) {
                    g_terminalAVOs.erase(it->second.avo);
                }
                g_terminalActors.erase(it);
                return false;
            }
            return true;
        }

        bool IsTerminal(RE::ActorValueOwner* a_avo)
        {
            if (!a_avo) {
                return false;
            }
            std::scoped_lock lock(g_terminalLock);
            const auto it = g_terminalAVOs.find(a_avo);
            if (it == g_terminalAVOs.end()) {
                return false;
            }
            if (IsExpired(it->second)) {
                g_terminalAVOs.erase(it);
                return false;
            }
            return true;
        }

        bool IsAbsoluteTarget(RE::Actor* a_actor)
        {
            return g_ctx.depth > 0 && g_ctx.target == a_actor;
        }

        bool IsAbsoluteTarget(RE::ActorValueOwner* a_avo)
        {
            return g_ctx.depth > 0 && g_ctx.targetAVO == a_avo;
        }

        void Hook_HandleHealthDamage(RE::Actor* a_self, RE::Actor* a_attacker, float a_damage)
        {
            if (!a_self || !g_fn.prevHandleHealth || !g_fn.vanillaHandleHealth) {
                return;
            }

            if (!IsAbsoluteAttacker(a_attacker)) {
                g_fn.prevHandleHealth(a_self, a_attacker, a_damage);
                return;
            }

            logger::debug("Absolute damage: attacker=0x{:08X}, target=0x{:08X}, input={}",
                a_attacker ? a_attacker->GetFormID() : 0,
                a_self->GetFormID(),
                a_damage);

            {
                ScopedAbsoluteContext absolute{ a_self };
                g_fn.vanillaHandleHealth(a_self, a_attacker, a_damage);
            }

            const auto health = a_self->GetActorValue(RE::ActorValue::kHealth);
            if (health <= 0.0F || a_self->IsDead()) {
                MarkTerminal(a_self);
            }
        }

        float Hook_CheckClampDamageModifier(RE::Actor* a_self, RE::ActorValue a_value, float a_delta)
        {
            const auto fn = IsAbsoluteTarget(a_self) ? g_fn.vanillaCheckClamp : g_fn.prevCheckClamp;
            return fn ? fn(a_self, a_value, a_delta) : a_delta;
        }

        void Hook_KillImpl(RE::Actor* a_self, RE::Actor* a_attacker, float a_damage, bool a_sendEvent, bool a_ragdollInstant)
        {
            const bool absolute = IsAbsoluteTarget(a_self);
            const auto fn = absolute ? g_fn.vanillaKillImpl : g_fn.prevKillImpl;
            if (fn) {
                fn(a_self, a_attacker, a_damage, a_sendEvent, a_ragdollInstant);
            }
            if (absolute) {
                MarkTerminal(a_self);
            }
        }

        void Hook_KillDying(RE::Actor* a_self)
        {
            const auto fn = IsAbsoluteTarget(a_self) ? g_fn.vanillaKillDying : g_fn.prevKillDying;
            if (fn) {
                fn(a_self);
            }
        }

        void Hook_Resurrect(RE::Actor* a_self, bool a_resetInventory, bool a_attach3D)
        {
            if (IsTerminal(a_self)) {
                logger::debug("Terminal death blocked Resurrect on 0x{:08X}", a_self ? a_self->GetFormID() : 0);
                return;
            }
            if (g_fn.prevResurrect) {
                g_fn.prevResurrect(a_self, a_resetInventory, a_attach3D);
            }
        }

        void Hook_SetBaseActorValue(RE::ActorValueOwner* a_self, RE::ActorValue a_value, float a_amount)
        {
            const auto fn = IsAbsoluteTarget(a_self) ? g_fn.vanillaSetBase : g_fn.prevSetBase;
            if (fn) {
                fn(a_self, a_value, a_amount);
            }
        }

        void Hook_ModBaseActorValue(RE::ActorValueOwner* a_self, RE::ActorValue a_value, float a_amount)
        {
            const auto fn = IsAbsoluteTarget(a_self) ? g_fn.vanillaModBase : g_fn.prevModBase;
            if (fn) {
                fn(a_self, a_value, a_amount);
            }
        }

        void Hook_ModActorValue(RE::ActorValueOwner* a_self, RE::ACTOR_VALUE_MODIFIER a_modifier, RE::ActorValue a_value, float a_amount)
        {
            if (a_value == RE::ActorValue::kHealth && IsTerminal(a_self) && a_amount > 0.0F) {
                logger::debug("Terminal death blocked positive Health ModActorValue ({})", a_amount);
                return;
            }
            const auto fn = IsAbsoluteTarget(a_self) ? g_fn.vanillaModAV : g_fn.prevModAV;
            if (fn) {
                fn(a_self, a_modifier, a_value, a_amount);
            }
        }

        void Hook_SetActorValue(RE::ActorValueOwner* a_self, RE::ActorValue a_value, float a_amount)
        {
            if (a_value == RE::ActorValue::kHealth && IsTerminal(a_self) && a_amount > 0.0F) {
                logger::debug("Terminal death blocked positive Health SetActorValue ({})", a_amount);
                return;
            }
            const auto fn = IsAbsoluteTarget(a_self) ? g_fn.vanillaSetAV : g_fn.prevSetAV;
            if (fn) {
                fn(a_self, a_value, a_amount);
            }
        }

        template <class Fn>
        Fn Pristine(std::uintptr_t a_vtable, std::size_t a_slot)
        {
            return reinterpret_cast<Fn>(g_pristine.ResolveVFunc(a_vtable, a_slot));
        }

        template <class Fn>
        Fn Current(std::uintptr_t a_vtable, std::size_t a_slot)
        {
            return reinterpret_cast<Fn>(*reinterpret_cast<std::uintptr_t*>(a_vtable + a_slot * sizeof(void*)));
        }

        template <class Fn>
        void EnsureHook(REL::Relocation<std::uintptr_t>& a_vtable, std::size_t a_slot, Fn a_hook, Fn& a_previous)
        {
            const auto hookAddress = reinterpret_cast<std::uintptr_t>(a_hook);
            const auto currentAddress = *reinterpret_cast<std::uintptr_t*>(a_vtable.address() + a_slot * sizeof(void*));
            if (currentAddress == hookAddress) {
                return;
            }
            a_previous = reinterpret_cast<Fn>(a_vtable.write_vfunc(a_slot, a_hook));
            logger::info("Hooked vtable 0x{:X}[0x{:X}]: prev=0x{:X}, ours=0x{:X}",
                a_vtable.address(), a_slot, reinterpret_cast<std::uintptr_t>(a_previous), hookAddress);
        }

        bool InstallOrRefreshHooks()
        {
            static REL::Relocation<std::uintptr_t> actorVTable{ RE::VTABLE_Actor[0] };
            static REL::Relocation<std::uintptr_t> avoVTable{ RE::VTABLE_ActorValueOwner[0] };

            if (!g_fn.vanillaHandleHealth) {
                g_fn.vanillaHandleHealth = Pristine<HandleHealthDamage_t>(actorVTable.address(), kActor_HandleHealthDamage);
                g_fn.vanillaKillImpl = Pristine<KillImpl_t>(actorVTable.address(), kActor_KillImpl);
                g_fn.vanillaCheckClamp = Pristine<CheckClampDamageModifier_t>(actorVTable.address(), kActor_CheckClampDamageModifier);
                g_fn.vanillaKillDying = Pristine<KillDying_t>(actorVTable.address(), kActor_KillDying);
                g_fn.vanillaResurrect = Pristine<Resurrect_t>(actorVTable.address(), kActor_Resurrect);

                g_fn.vanillaSetBase = Pristine<SetBaseActorValue_t>(avoVTable.address(), kAVO_SetBaseActorValue);
                g_fn.vanillaModBase = Pristine<ModBaseActorValue_t>(avoVTable.address(), kAVO_ModBaseActorValue);
                g_fn.vanillaModAV = Pristine<ModActorValue_t>(avoVTable.address(), kAVO_ModActorValue);
                g_fn.vanillaSetAV = Pristine<SetActorValue_t>(avoVTable.address(), kAVO_SetActorValue);

                const bool complete = g_fn.vanillaHandleHealth && g_fn.vanillaKillImpl && g_fn.vanillaCheckClamp &&
                    g_fn.vanillaKillDying && g_fn.vanillaResurrect && g_fn.vanillaSetBase &&
                    g_fn.vanillaModBase && g_fn.vanillaModAV && g_fn.vanillaSetAV;
                if (!complete) {
                    logger::critical("Could not recover all pristine Skyrim vtable functions. Hooks NOT installed.");
                    return false;
                }

                logger::info("Pristine Skyrim vtable functions recovered from the on-disk executable");
            }

            EnsureHook(actorVTable, kActor_HandleHealthDamage, Hook_HandleHealthDamage, g_fn.prevHandleHealth);
            EnsureHook(actorVTable, kActor_KillImpl, Hook_KillImpl, g_fn.prevKillImpl);
            EnsureHook(actorVTable, kActor_CheckClampDamageModifier, Hook_CheckClampDamageModifier, g_fn.prevCheckClamp);
            EnsureHook(actorVTable, kActor_KillDying, Hook_KillDying, g_fn.prevKillDying);
            EnsureHook(actorVTable, kActor_Resurrect, Hook_Resurrect, g_fn.prevResurrect);

            EnsureHook(avoVTable, kAVO_SetBaseActorValue, Hook_SetBaseActorValue, g_fn.prevSetBase);
            EnsureHook(avoVTable, kAVO_ModBaseActorValue, Hook_ModBaseActorValue, g_fn.prevModBase);
            EnsureHook(avoVTable, kAVO_ModActorValue, Hook_ModActorValue, g_fn.prevModAV);
            EnsureHook(avoVTable, kAVO_SetActorValue, Hook_SetActorValue, g_fn.prevSetAV);
            return true;
        }

        void SetupLog()
        {
            auto path = logger::log_directory();
            if (!path) {
                return;
            }
            *path /= "UniversalCombatArbiter.log";
            auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true);
            auto log = std::make_shared<spdlog::logger>("global", std::move(sink));
            log->set_level(spdlog::level::debug);
            log->flush_on(spdlog::level::debug);
            spdlog::set_default_logger(std::move(log));
            spdlog::set_pattern("[%H:%M:%S.%e] [%l] %v");
        }

        void MessageHandler(SKSE::MessagingInterface::Message* a_message)
        {
            if (!a_message) {
                return;
            }

            switch (a_message->type) {
            case SKSE::MessagingInterface::kPostPostLoad:
                // Most SKSE plugins have finished their initial hook installation by here.
                InstallOrRefreshHooks();
                break;
            case SKSE::MessagingInterface::kDataLoaded:
                ResolveConfiguredAttacker();
                // Re-wrap once immediately and once on the game task queue.  The latter intentionally
                // runs after DataLoaded listeners that may install their own vtable hooks.
                InstallOrRefreshHooks();
                if (auto* tasks = SKSE::GetTaskInterface()) {
                    tasks->AddTask([]() { InstallOrRefreshHooks(); });
                }
                break;
            case SKSE::MessagingInterface::kPostLoadGame:
            case SKSE::MessagingInterface::kNewGame:
                if (auto* tasks = SKSE::GetTaskInterface()) {
                    tasks->AddTask([]() {
                        ResolveConfiguredAttacker();
                        InstallOrRefreshHooks();
                    });
                }
                break;
            default:
                break;
            }
        }
    }

    bool Initialize(const SKSE::LoadInterface* a_skse)
    {
        SetupLog();
        logger::info("UniversalCombatArbiter loading; runtime {}", a_skse->RuntimeVersion().string());

        LoadConfig();
        if (!g_pristine.Load()) {
            logger::critical("Failed to read the pristine Skyrim executable; plugin disabled");
            return true;
        }

        auto* messaging = SKSE::GetMessagingInterface();
        if (!messaging || !messaging->RegisterListener(MessageHandler)) {
            logger::critical("Could not register SKSE message listener");
            return false;
        }

        return true;
    }
}

SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
    SKSE::Init(a_skse);
    return UCA::Initialize(a_skse);
}
