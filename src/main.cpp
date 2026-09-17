#include "PCH.h"

#include <fmt/format.h>
#include <initializer_list>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

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

        constexpr std::size_t kAVO_GetActorValue = 0x01;
        constexpr std::size_t kAVO_SetBaseActorValue = 0x04;
        constexpr std::size_t kAVO_ModActorValue = 0x05;
        constexpr std::size_t kAVO_RestoreActorValue = 0x06;
        constexpr std::size_t kAVO_SetActorValue = 0x07;

        struct Config
        {
            bool traceHitEvents{ true };
            bool traceVTableCalls{ true };
            bool traceEntryCalls{ true };
            bool traceLifecycle{ true };
        };

        Config g_config;
        bool g_runtime1170{ false };

        std::filesystem::path GetIniPath()
        {
            return std::filesystem::path{ "Data" } / "SKSE" / "Plugins" /
                   "UniversalCombatArbiter.ini";
        }

        std::string ReadIniString(const char* a_key, const char* a_default = "")
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

        bool ReadIniBool(const char* a_key, bool a_default)
        {
            const auto raw = ReadIniString(a_key, a_default ? "1" : "0");
            return raw == "1" || raw == "true" || raw == "TRUE" ||
                   raw == "yes" || raw == "YES";
        }

        void LoadConfig()
        {
            g_config.traceHitEvents = ReadIniBool("bTraceHitEvents", true);
            g_config.traceVTableCalls = ReadIniBool("bTraceVTableCalls", true);
            g_config.traceEntryCalls = ReadIniBool("bTraceEntryCalls", true);
            g_config.traceLifecycle = ReadIniBool("bTraceLifecycle", true);

            logger::info(
                "PoC3 config: hitEvents={}, vtableCalls={}, entryCalls={}, lifecycle={}",
                g_config.traceHitEvents,
                g_config.traceVTableCalls,
                g_config.traceEntryCalls,
                g_config.traceLifecycle);
        }

        std::uint64_t NextTraceID()
        {
            static volatile LONG64 sequence = 0;
            return static_cast<std::uint64_t>(
                ::InterlockedIncrement64(&sequence));
        }

        struct AddressInfo
        {
            std::uintptr_t address{};
            std::uintptr_t moduleBase{};
            std::uintptr_t offset{};
            std::string moduleName{ "<non-module>" };
        };

        AddressInfo DescribeAddress(std::uintptr_t a_address)
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
                reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
            result.offset = a_address - result.moduleBase;

            std::array<char, 32768> path{};
            const auto count = ::GetModuleFileNameA(
                reinterpret_cast<HMODULE>(mbi.AllocationBase),
                path.data(),
                static_cast<DWORD>(path.size()));

            if (count > 0 && count < path.size()) {
                result.moduleName =
                    std::filesystem::path{ path.data() }.filename().string();
            }

            return result;
        }

        std::string FormatAddress(std::uintptr_t a_address)
        {
            const auto info = DescribeAddress(a_address);

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

        std::string MemoryBytes(
            std::uintptr_t a_address,
            std::size_t a_count)
        {
            if (!a_address || a_count == 0) {
                return {};
            }

            std::string out;
            out.reserve(a_count * 3);

            const auto* bytes =
                reinterpret_cast<const std::uint8_t*>(a_address);

            for (std::size_t i = 0; i < a_count; ++i) {
                if (i != 0) {
                    out.push_back(' ');
                }
                out += fmt::format("{:02X}", bytes[i]);
            }

            return out;
        }

        bool PrefixMatches(
            std::uintptr_t a_address,
            std::initializer_list<std::uint8_t> a_expected)
        {
            if (!a_address || a_expected.size() == 0) {
                return false;
            }

            const auto* current =
                reinterpret_cast<const std::uint8_t*>(a_address);

            return std::equal(
                a_expected.begin(),
                a_expected.end(),
                current);
        }

        void WriteNops(
            std::uintptr_t a_address,
            std::size_t a_count)
        {
            if (!a_address || a_count == 0) {
                return;
            }

            DWORD oldProtect = 0;
            if (!::VirtualProtect(
                    reinterpret_cast<void*>(a_address),
                    a_count,
                    PAGE_EXECUTE_READWRITE,
                    &oldProtect)) {
                logger::error(
                    "VirtualProtect failed while filling NOPs at 0x{:X}",
                    a_address);
                return;
            }

            std::memset(
                reinterpret_cast<void*>(a_address),
                0x90,
                a_count);

            ::FlushInstructionCache(
                ::GetCurrentProcess(),
                reinterpret_cast<const void*>(a_address),
                a_count);

            DWORD ignored = 0;
            ::VirtualProtect(
                reinterpret_cast<void*>(a_address),
                a_count,
                oldProtect,
                &ignored);
        }

        void EmitAbsoluteJump(
            std::uint8_t* a_dst,
            std::uintptr_t a_target)
        {
            static constexpr std::array<std::uint8_t, 6> prefix{
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00
            };

            std::memcpy(
                a_dst,
                prefix.data(),
                prefix.size());

            std::memcpy(
                a_dst + prefix.size(),
                &a_target,
                sizeof(a_target));
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

                _runtimeBase =
                    reinterpret_cast<std::uintptr_t>(module);

                std::array<wchar_t, 32768> path{};
                const auto count = ::GetModuleFileNameW(
                    module,
                    path.data(),
                    static_cast<DWORD>(path.size()));

                if (count == 0 || count >= path.size()) {
                    logger::error("GetModuleFileNameW failed");
                    return false;
                }

                std::ifstream input(
                    std::filesystem::path{ path.data() },
                    std::ios::binary | std::ios::ate);

                if (!input) {
                    logger::error(
                        "Could not open Skyrim executable on disk");
                    return false;
                }

                const auto size = input.tellg();
                if (size <= 0) {
                    return false;
                }

                _bytes.resize(static_cast<std::size_t>(size));
                input.seekg(0, std::ios::beg);
                input.read(
                    reinterpret_cast<char*>(_bytes.data()),
                    static_cast<std::streamsize>(size));

                if (!input) {
                    logger::error("Could not read Skyrim executable");
                    return false;
                }

                if (_bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
                    return false;
                }

                const auto* dos =
                    reinterpret_cast<const IMAGE_DOS_HEADER*>(_bytes.data());

                if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
                    dos->e_lfanew <= 0) {
                    return false;
                }

                if (static_cast<std::size_t>(dos->e_lfanew) +
                        sizeof(IMAGE_NT_HEADERS64) >
                    _bytes.size()) {
                    return false;
                }

                const auto* nt =
                    reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                        _bytes.data() + dos->e_lfanew);

                if (nt->Signature != IMAGE_NT_SIGNATURE ||
                    nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                    return false;
                }

                _preferredBase =
                    static_cast<std::uintptr_t>(nt->OptionalHeader.ImageBase);
                _sizeOfImage = nt->OptionalHeader.SizeOfImage;
                _sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;

                const auto* first = IMAGE_FIRST_SECTION(nt);
                _sections.assign(
                    first,
                    first + nt->FileHeader.NumberOfSections);

                logger::info(
                    "Pristine executable loaded for vtable recovery: "
                    "runtimeBase=0x{:X}, preferredBase=0x{:X}, imageSize=0x{:X}",
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
                    a_runtimeVTable < _runtimeBase) {
                    return 0;
                }

                const auto vtableRva =
                    a_runtimeVTable - _runtimeBase;

                const auto entryRva =
                    vtableRva +
                    (a_slot * sizeof(std::uintptr_t));

                const auto fileOffset =
                    RvaToFileOffset(entryRva);

                if (!fileOffset ||
                    *fileOffset + sizeof(std::uint64_t) > _bytes.size()) {
                    return 0;
                }

                std::uint64_t preferredVA = 0;
                std::memcpy(
                    &preferredVA,
                    _bytes.data() + *fileOffset,
                    sizeof(preferredVA));

                if (preferredVA < _preferredBase ||
                    preferredVA >= (_preferredBase + _sizeOfImage)) {
                    return 0;
                }

                return _runtimeBase +
                       static_cast<std::uintptr_t>(
                           preferredVA - _preferredBase);
            }

        private:
            [[nodiscard]]
            std::optional<std::size_t>
            RvaToFileOffset(std::uintptr_t a_rva) const
            {
                if (a_rva < _sizeOfHeaders) {
                    return static_cast<std::size_t>(a_rva);
                }

                for (const auto& section : _sections) {
                    const auto begin =
                        static_cast<std::uintptr_t>(section.VirtualAddress);

                    const auto span =
                        static_cast<std::uintptr_t>(
                            std::max(
                                section.Misc.VirtualSize,
                                section.SizeOfRawData));

                    if (a_rva >= begin && a_rva < begin + span) {
                        const auto delta = a_rva - begin;

                        if (delta >= section.SizeOfRawData) {
                            return std::nullopt;
                        }

                        return static_cast<std::size_t>(
                            section.PointerToRawData + delta);
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

        using HandleHealthDamage_t =
            void (*)(RE::Actor*, RE::Actor*, float);

        using KillImpl_t =
            void (*)(RE::Actor*, RE::Actor*, float, bool, bool);

        using CheckClampDamageModifier_t =
            float (*)(RE::Actor*, RE::ActorValue, float);

        using KillDying_t =
            void (*)(RE::Actor*);

        using Resurrect_t =
            void (*)(RE::Actor*, bool, bool);

        using SetBaseActorValue_t =
            void (*)(RE::ActorValueOwner*, RE::ActorValue, float);

        using ModActorValue_t =
            void (*)(RE::ActorValueOwner*, RE::ActorValue, float);

        using RestoreActorValue_t =
            void (*)(
                RE::ActorValueOwner*,
                RE::ACTOR_VALUE_MODIFIER,
                RE::ActorValue,
                float);

        using SetActorValue_t =
            void (*)(RE::ActorValueOwner*, RE::ActorValue, float);

        struct VTableFunctions
        {
            HandleHealthDamage_t handleHealth{};
            KillImpl_t killImpl{};
            CheckClampDamageModifier_t checkClamp{};
            KillDying_t killDying{};
            Resurrect_t resurrect{};

            SetBaseActorValue_t setBase{};
            ModActorValue_t modAV{};
            RestoreActorValue_t restoreAV{};
            SetActorValue_t setAV{};
        };

        struct EntryFunctions
        {
            HandleHealthDamage_t handleHealth{};
            KillImpl_t killImpl{};
            CheckClampDamageModifier_t checkClamp{};

            ModActorValue_t modAV{};
            RestoreActorValue_t restoreAV{};
            SetActorValue_t setAV{};
        };

        VTableFunctions g_vtablePrev{};
        EntryFunctions g_entryOriginal{};

        struct EngineTargets
        {
            std::uintptr_t handleHealth{};
            std::uintptr_t killImpl{};
            std::uintptr_t checkClamp{};

            std::uintptr_t setBase{};
            std::uintptr_t modAV{};
            std::uintptr_t restoreAV{};
            std::uintptr_t setAV{};
        };

        EngineTargets g_targets{};

        std::uintptr_t g_liveActorAVOVTable{};
        std::intptr_t g_actorToAVOOffset{};

        float ReadHealth(RE::Actor* a_actor)
        {
            if (!a_actor) {
                return 0.0F;
            }

            return a_actor->GetActorValue(
                RE::ActorValue::kHealth);
        }

        float ReadHealth(RE::ActorValueOwner* a_owner)
        {
            if (!a_owner) {
                return 0.0F;
            }

            return a_owner->GetActorValue(
                RE::ActorValue::kHealth);
        }

        template <class Fn>
        Fn WriteVFuncRaw(
            std::uintptr_t a_vtable,
            std::size_t a_slot,
            Fn a_hook)
        {
            if (!a_vtable || !a_hook) {
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
                    PAGE_READWRITE,
                    &oldProtect)) {
                logger::error(
                    "VirtualProtect failed for vtable=0x{:X}[0x{:X}]",
                    a_vtable,
                    a_slot);
                return nullptr;
            }

            const auto previous = *entry;
            *entry =
                reinterpret_cast<std::uintptr_t>(a_hook);

            DWORD ignored = 0;
            ::VirtualProtect(
                entry,
                sizeof(*entry),
                oldProtect,
                &ignored);

            return reinterpret_cast<Fn>(previous);
        }

        template <class Fn>
        void EnsureVTableHook(
            std::uintptr_t a_vtable,
            std::size_t a_slot,
            Fn a_hook,
            Fn& a_previous,
            std::string_view a_label)
        {
            if (!g_config.traceVTableCalls ||
                !a_vtable ||
                !a_hook) {
                return;
            }

            const auto hookAddress =
                reinterpret_cast<std::uintptr_t>(a_hook);

            const auto currentAddress =
                *reinterpret_cast<std::uintptr_t*>(
                    a_vtable +
                    a_slot * sizeof(void*));

            if (currentAddress == hookAddress) {
                return;
            }

            a_previous =
                WriteVFuncRaw(
                    a_vtable,
                    a_slot,
                    a_hook);

            logger::info(
                "[vhook] {} vtable=0x{:X}[0x{:X}] prev={} ours={}",
                a_label,
                a_vtable,
                a_slot,
                FormatAddress(
                    reinterpret_cast<std::uintptr_t>(a_previous)),
                FormatAddress(hookAddress));
        }

        bool EntryBranchStillPointsTo(
            std::uintptr_t a_target,
            std::uintptr_t a_hook)
        {
            if (!a_target || !a_hook) {
                return false;
            }

            const auto* src =
                reinterpret_cast<const std::uint8_t*>(a_target);

            if (src[0] != 0xE9) {
                return false;
            }

            std::int32_t disp = 0;
            std::memcpy(
                &disp,
                src + 1,
                sizeof(disp));

            const auto island =
                static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(a_target + 5) +
                    static_cast<std::intptr_t>(disp));

            const auto* stub =
                reinterpret_cast<const std::uint8_t*>(island);

            static constexpr std::array<std::uint8_t, 6> expected{
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00
            };

            if (!std::equal(
                    expected.begin(),
                    expected.end(),
                    stub)) {
                return false;
            }

            std::uintptr_t destination = 0;
            std::memcpy(
                &destination,
                stub + expected.size(),
                sizeof(destination));

            return destination == a_hook;
        }

        template <class Fn>
        bool InstallEntryHook(
            std::string_view a_label,
            std::uintptr_t a_target,
            Fn a_hook,
            Fn& a_original,
            std::initializer_list<std::uint8_t> a_expectedPrefix)
        {
            if (!g_config.traceEntryCalls ||
                !g_runtime1170) {
                return false;
            }

            if (a_original) {
                const auto hookAddress =
                    reinterpret_cast<std::uintptr_t>(a_hook);

                const bool intact =
                    EntryBranchStillPointsTo(
                        a_target,
                        hookAddress);

                if (!intact) {
                    logger::warn(
                        "[entry-check] {} entry detour is no longer ours; "
                        "current bytes=[{}]. PoC3 will not fight for the "
                        "function entry.",
                        a_label,
                        MemoryBytes(a_target, 16));
                }

                return intact;
            }

            if (!a_target ||
                !a_hook ||
                a_expectedPrefix.size() < 5) {
                logger::warn(
                    "[entry-install] {} invalid target/hook/prefix",
                    a_label);
                return false;
            }

            const auto previewCount =
                std::max<std::size_t>(
                    16,
                    a_expectedPrefix.size());

            const bool prefixOK =
                PrefixMatches(
                    a_target,
                    a_expectedPrefix);

            logger::info(
                "[prologue] {} target={} prefixMatch={} bytes=[{}]",
                a_label,
                FormatAddress(a_target),
                prefixOK,
                MemoryBytes(
                    a_target,
                    previewCount));

            if (!prefixOK) {
                logger::warn(
                    "[entry-install] {} NOT patched because the "
                    "1.6.1170 prologue did not match. "
                    "This can indicate an existing inline hook or "
                    "a different engine build.",
                    a_label);
                return false;
            }

            const auto stolenLength =
                a_expectedPrefix.size();

            auto& trampoline =
                SKSE::GetTrampoline();

            auto* gateway =
                static_cast<std::uint8_t*>(
                    trampoline.allocate(
                        stolenLength + 14));

            std::memcpy(
                gateway,
                reinterpret_cast<const void*>(
                    a_target),
                stolenLength);

            EmitAbsoluteJump(
                gateway + stolenLength,
                a_target + stolenLength);

            a_original =
                reinterpret_cast<Fn>(
                    gateway);

            (void)trampoline.write_branch<5>(
                a_target,
                a_hook);

            if (stolenLength > 5) {
                WriteNops(
                    a_target + 5,
                    stolenLength - 5);
            }

            ::FlushInstructionCache(
                ::GetCurrentProcess(),
                reinterpret_cast<const void*>(
                    a_target),
                stolenLength);

            logger::info(
                "[entry-install] {} target={} gateway=0x{:X} stolen={} bytes",
                a_label,
                FormatAddress(a_target),
                reinterpret_cast<std::uintptr_t>(
                    gateway),
                stolenLength);

            return true;
        }

        void DescribeVTableSlot(
            std::string_view a_label,
            std::uintptr_t a_vtable,
            std::size_t a_slot)
        {
            if (!a_vtable) {
                logger::warn(
                    "[slot] {} vtable=<null>",
                    a_label);
                return;
            }

            const auto current =
                *reinterpret_cast<
                    const std::uintptr_t*>(
                        a_vtable +
                        a_slot * sizeof(void*));

            const auto pristine =
                g_pristine.ResolveVFunc(
                    a_vtable,
                    a_slot);

            logger::info(
                "[slot] {} vtable=0x{:X}[0x{:X}] "
                "current={} pristine={} same={}",
                a_label,
                a_vtable,
                a_slot,
                FormatAddress(current),
                pristine ?
                    FormatAddress(pristine) :
                    std::string{ "<unavailable>" },
                pristine != 0 &&
                    current == pristine);
        }

        class HitEventSink final :
            public RE::BSTEventSink<RE::TESHitEvent>
        {
        public:
            RE::BSEventNotifyControl ProcessEvent(
                const RE::TESHitEvent* a_event,
                RE::BSTEventSource<RE::TESHitEvent>*) override
            {
                if (!a_event ||
                    !g_config.traceHitEvents) {
                    return RE::BSEventNotifyControl::kContinue;
                }

                auto* targetRef =
                    a_event->target.get();

                auto* causeRef =
                    a_event->cause.get();

                auto* targetActor =
                    targetRef ?
                        targetRef->As<RE::Actor>() :
                        nullptr;

                auto* causeActor =
                    causeRef ?
                        causeRef->As<RE::Actor>() :
                        nullptr;

                auto* targetAVO =
                    targetActor ?
                        targetActor->AsActorValueOwner() :
                        nullptr;

                const auto id =
                    NextTraceID();

                logger::info(
                    "[hit:{}] targetForm=0x{:08X} "
                    "targetActor=0x{:X} targetAVO=0x{:X} "
                    "causeForm=0x{:08X} causeActor=0x{:X} "
                    "source=0x{:08X} projectile=0x{:08X} "
                    "flags=0x{:02X} health={} tid={}",
                    id,
                    targetRef ?
                        targetRef->GetFormID() :
                        0,
                    reinterpret_cast<std::uintptr_t>(
                        targetActor),
                    reinterpret_cast<std::uintptr_t>(
                        targetAVO),
                    causeRef ?
                        causeRef->GetFormID() :
                        0,
                    reinterpret_cast<std::uintptr_t>(
                        causeActor),
                    a_event->source,
                    a_event->projectile,
                    static_cast<std::uint32_t>(
                        a_event->flags.underlying()),
                    targetActor ?
                        ReadHealth(targetActor) :
                        0.0F,
                    ::GetCurrentThreadId());

                return RE::BSEventNotifyControl::kContinue;
            }
        };

        HitEventSink g_hitSink;
        bool g_hitSinkRegistered{ false };

        void RegisterHitEventSink()
        {
            if (g_hitSinkRegistered ||
                !g_config.traceHitEvents) {
                return;
            }

            auto* holder =
                RE::ScriptEventSourceHolder::GetSingleton();

            if (!holder) {
                logger::warn(
                    "[hit] ScriptEventSourceHolder unavailable");
                return;
            }

            holder->AddEventSink<RE::TESHitEvent>(
                &g_hitSink);

            g_hitSinkRegistered = true;
            logger::info("[hit] TESHitEvent sink registered");
        }

        void V_HandleHealthDamage(
            RE::Actor* a_self,
            RE::Actor* a_attacker,
            float a_damage)
        {
            if (!g_vtablePrev.handleHealth) {
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] ENTER HandleHealthDamage "
                "self=0x{:08X} attacker=0x{:08X} "
                "input={} healthBefore={} tid={} caller={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                a_attacker ? a_attacker->GetFormID() : 0,
                a_damage,
                before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            g_vtablePrev.handleHealth(
                a_self,
                a_attacker,
                a_damage);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] EXIT  HandleHealthDamage "
                "self=0x{:08X} healthAfter={} "
                "observedDelta={} dead={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                after,
                after - before,
                a_self ? a_self->IsDead() : false);
        }

        float V_CheckClampDamageModifier(
            RE::Actor* a_self,
            RE::ActorValue a_value,
            float a_delta)
        {
            if (!g_vtablePrev.checkClamp) {
                return a_delta;
            }

            if (a_value != RE::ActorValue::kHealth) {
                return g_vtablePrev.checkClamp(
                    a_self,
                    a_value,
                    a_delta);
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            const auto result =
                g_vtablePrev.checkClamp(
                    a_self,
                    a_value,
                    a_delta);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] CheckClampDamageModifier "
                "self=0x{:08X} input={} result={} "
                "healthBefore={} healthAfter={} "
                "tid={} caller={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                a_delta,
                result,
                before,
                after,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            return result;
        }

        void V_KillImpl(
            RE::Actor* a_self,
            RE::Actor* a_attacker,
            float a_damage,
            bool a_sendEvent,
            bool a_ragdollInstant)
        {
            if (!g_vtablePrev.killImpl) {
                return;
            }

            if (!g_config.traceLifecycle) {
                g_vtablePrev.killImpl(
                    a_self,
                    a_attacker,
                    a_damage,
                    a_sendEvent,
                    a_ragdollInstant);
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] ENTER KillImpl "
                "self=0x{:08X} attacker=0x{:08X} "
                "damage={} healthBefore={} "
                "sendEvent={} ragdoll={} tid={} caller={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                a_attacker ? a_attacker->GetFormID() : 0,
                a_damage,
                before,
                a_sendEvent,
                a_ragdollInstant,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            g_vtablePrev.killImpl(
                a_self,
                a_attacker,
                a_damage,
                a_sendEvent,
                a_ragdollInstant);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] EXIT  KillImpl "
                "self=0x{:08X} healthAfter={} "
                "observedDelta={} dead={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                after,
                after - before,
                a_self ? a_self->IsDead() : false);
        }

        void V_KillDying(RE::Actor* a_self)
        {
            if (!g_vtablePrev.killDying) {
                return;
            }

            if (g_config.traceLifecycle) {
                logger::info(
                    "[vcall:{}] KillDying self=0x{:08X} "
                    "health={} tid={} caller={}",
                    NextTraceID(),
                    a_self ? a_self->GetFormID() : 0,
                    ReadHealth(a_self),
                    ::GetCurrentThreadId(),
                    FormatAddress(
                        reinterpret_cast<std::uintptr_t>(
                            _ReturnAddress())));
            }

            g_vtablePrev.killDying(a_self);
        }

        void V_Resurrect(
            RE::Actor* a_self,
            bool a_resetInventory,
            bool a_attach3D)
        {
            if (!g_vtablePrev.resurrect) {
                return;
            }

            if (g_config.traceLifecycle) {
                logger::info(
                    "[vcall:{}] Resurrect self=0x{:08X} "
                    "health={} resetInventory={} attach3D={} "
                    "tid={} caller={}",
                    NextTraceID(),
                    a_self ? a_self->GetFormID() : 0,
                    ReadHealth(a_self),
                    a_resetInventory,
                    a_attach3D,
                    ::GetCurrentThreadId(),
                    FormatAddress(
                        reinterpret_cast<std::uintptr_t>(
                            _ReturnAddress())));
            }

            g_vtablePrev.resurrect(
                a_self,
                a_resetInventory,
                a_attach3D);
        }

        void V_SetBaseActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_vtablePrev.setBase) {
                return;
            }

            if (a_value != RE::ActorValue::kHealth) {
                g_vtablePrev.setBase(
                    a_self,
                    a_value,
                    a_amount);
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            g_vtablePrev.setBase(
                a_self,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] SetBaseActorValue(Health) "
                "avo=0x{:X} amount={} "
                "healthBefore={} healthAfter={} "
                "observedDelta={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                a_amount,
                before,
                after,
                after - before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));
        }

        void V_ModActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_vtablePrev.modAV) {
                return;
            }

            if (a_value != RE::ActorValue::kHealth) {
                g_vtablePrev.modAV(
                    a_self,
                    a_value,
                    a_amount);
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            g_vtablePrev.modAV(
                a_self,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] ModActorValue(Health) "
                "avo=0x{:X} amount={} "
                "healthBefore={} healthAfter={} "
                "observedDelta={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                a_amount,
                before,
                after,
                after - before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));
        }

        void V_RestoreActorValue(
            RE::ActorValueOwner* a_self,
            RE::ACTOR_VALUE_MODIFIER a_modifier,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_vtablePrev.restoreAV) {
                return;
            }

            if (a_value != RE::ActorValue::kHealth) {
                g_vtablePrev.restoreAV(
                    a_self,
                    a_modifier,
                    a_value,
                    a_amount);
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            g_vtablePrev.restoreAV(
                a_self,
                a_modifier,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] RestoreActorValue(Health) "
                "avo=0x{:X} modifier={} amount={} "
                "healthBefore={} healthAfter={} "
                "observedDelta={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                static_cast<std::int32_t>(a_modifier),
                a_amount,
                before,
                after,
                after - before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));
        }

        void V_SetActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_vtablePrev.setAV) {
                return;
            }

            if (a_value != RE::ActorValue::kHealth) {
                g_vtablePrev.setAV(
                    a_self,
                    a_value,
                    a_amount);
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            g_vtablePrev.setAV(
                a_self,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[vcall:{}] SetActorValue(Health) "
                "avo=0x{:X} amount={} "
                "healthBefore={} healthAfter={} "
                "observedDelta={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                a_amount,
                before,
                after,
                after - before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));
        }

        void E_HandleHealthDamage(
            RE::Actor* a_self,
            RE::Actor* a_attacker,
            float a_damage)
        {
            if (!g_entryOriginal.handleHealth) {
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] ENTER HandleHealthDamage "
                "self=0x{:08X} attacker=0x{:08X} "
                "input={} healthBefore={} tid={} caller={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                a_attacker ? a_attacker->GetFormID() : 0,
                a_damage,
                before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            g_entryOriginal.handleHealth(
                a_self,
                a_attacker,
                a_damage);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] EXIT  HandleHealthDamage "
                "self=0x{:08X} healthAfter={} "
                "observedDelta={} dead={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                after,
                after - before,
                a_self ? a_self->IsDead() : false);
        }

        float E_CheckClampDamageModifier(
            RE::Actor* a_self,
            RE::ActorValue a_value,
            float a_delta)
        {
            if (!g_entryOriginal.checkClamp) {
                return a_delta;
            }

            if (a_value != RE::ActorValue::kHealth) {
                return g_entryOriginal.checkClamp(
                    a_self,
                    a_value,
                    a_delta);
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            const auto result =
                g_entryOriginal.checkClamp(
                    a_self,
                    a_value,
                    a_delta);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] CheckClampDamageModifier "
                "self=0x{:08X} input={} result={} "
                "healthBefore={} healthAfter={} "
                "tid={} caller={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                a_delta,
                result,
                before,
                after,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            return result;
        }

        void E_KillImpl(
            RE::Actor* a_self,
            RE::Actor* a_attacker,
            float a_damage,
            bool a_sendEvent,
            bool a_ragdollInstant)
        {
            if (!g_entryOriginal.killImpl) {
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] ENTER KillImpl "
                "self=0x{:08X} attacker=0x{:08X} "
                "damage={} healthBefore={} "
                "sendEvent={} ragdoll={} tid={} caller={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                a_attacker ? a_attacker->GetFormID() : 0,
                a_damage,
                before,
                a_sendEvent,
                a_ragdollInstant,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            g_entryOriginal.killImpl(
                a_self,
                a_attacker,
                a_damage,
                a_sendEvent,
                a_ragdollInstant);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] EXIT  KillImpl "
                "self=0x{:08X} healthAfter={} "
                "observedDelta={} dead={}",
                id,
                a_self ? a_self->GetFormID() : 0,
                after,
                after - before,
                a_self ? a_self->IsDead() : false);
        }

        void E_ModActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_entryOriginal.modAV) {
                return;
            }

            if (a_value != RE::ActorValue::kHealth) {
                g_entryOriginal.modAV(
                    a_self,
                    a_value,
                    a_amount);
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] ENTER ModActorValue(Health) "
                "avo=0x{:X} amount={} healthBefore={} "
                "tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                a_amount,
                before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            g_entryOriginal.modAV(
                a_self,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] EXIT  ModActorValue(Health) "
                "avo=0x{:X} healthAfter={} observedDelta={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                after,
                after - before);
        }

        void E_RestoreActorValue(
            RE::ActorValueOwner* a_self,
            RE::ACTOR_VALUE_MODIFIER a_modifier,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_entryOriginal.restoreAV) {
                return;
            }

            if (a_value != RE::ActorValue::kHealth) {
                g_entryOriginal.restoreAV(
                    a_self,
                    a_modifier,
                    a_value,
                    a_amount);
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] ENTER RestoreActorValue(Health) "
                "avo=0x{:X} modifier={} amount={} "
                "healthBefore={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                static_cast<std::int32_t>(a_modifier),
                a_amount,
                before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            g_entryOriginal.restoreAV(
                a_self,
                a_modifier,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] EXIT  RestoreActorValue(Health) "
                "avo=0x{:X} healthAfter={} observedDelta={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                after,
                after - before);
        }

        void E_SetActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_entryOriginal.setAV) {
                return;
            }

            if (a_value != RE::ActorValue::kHealth) {
                g_entryOriginal.setAV(
                    a_self,
                    a_value,
                    a_amount);
                return;
            }

            const auto id = NextTraceID();
            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            const auto before =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] ENTER SetActorValue(Health) "
                "avo=0x{:X} amount={} healthBefore={} "
                "tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                a_amount,
                before,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            g_entryOriginal.setAV(
                a_self,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(a_self);

            logger::info(
                "[entry:{}] EXIT  SetActorValue(Health) "
                "avo=0x{:X} healthAfter={} observedDelta={}",
                id,
                reinterpret_cast<std::uintptr_t>(a_self),
                after,
                after - before);
        }

        std::uintptr_t DiscoverLiveActorAVOVTable()
        {
            auto* player =
                RE::PlayerCharacter::GetSingleton();

            auto* avo =
                player ?
                    player->AsActorValueOwner() :
                    nullptr;

            if (!player || !avo) {
                return 0;
            }

            g_actorToAVOOffset =
                static_cast<std::intptr_t>(
                    reinterpret_cast<std::uintptr_t>(avo) -
                    reinterpret_cast<std::uintptr_t>(player));

            return *reinterpret_cast<
                const std::uintptr_t*>(avo);
        }

        void ResolveActorTargets(
            std::uintptr_t a_actorVTable)
        {
            if (!g_targets.handleHealth) {
                g_targets.handleHealth =
                    g_pristine.ResolveVFunc(
                        a_actorVTable,
                        kActor_HandleHealthDamage);

                g_targets.killImpl =
                    g_pristine.ResolveVFunc(
                        a_actorVTable,
                        kActor_KillImpl);

                g_targets.checkClamp =
                    g_pristine.ResolveVFunc(
                        a_actorVTable,
                        kActor_CheckClampDamageModifier);
            }
        }

        void ResolveAVOTargets(
            std::uintptr_t a_liveAVOVTable)
        {
            if (!g_targets.setBase) {
                g_targets.setBase =
                    g_pristine.ResolveVFunc(
                        a_liveAVOVTable,
                        kAVO_SetBaseActorValue);

                g_targets.modAV =
                    g_pristine.ResolveVFunc(
                        a_liveAVOVTable,
                        kAVO_ModActorValue);

                g_targets.restoreAV =
                    g_pristine.ResolveVFunc(
                        a_liveAVOVTable,
                        kAVO_RestoreActorValue);

                g_targets.setAV =
                    g_pristine.ResolveVFunc(
                        a_liveAVOVTable,
                        kAVO_SetActorValue);
            }
        }

        void InstallActorEntryHooks()
        {
            if (!g_config.traceEntryCalls ||
                !g_runtime1170) {
                return;
            }

            InstallEntryHook(
                "Skyrim::Actor::HandleHealthDamage",
                g_targets.handleHealth,
                E_HandleHealthDamage,
                g_entryOriginal.handleHealth,
                { 0x48, 0x89, 0x5C, 0x24, 0x08 });

            InstallEntryHook(
                "Skyrim::Actor::CheckClampDamageModifier",
                g_targets.checkClamp,
                E_CheckClampDamageModifier,
                g_entryOriginal.checkClamp,
                { 0x48, 0x89, 0x5C, 0x24, 0x08 });

            InstallEntryHook(
                "Skyrim::Actor::KillImpl",
                g_targets.killImpl,
                E_KillImpl,
                g_entryOriginal.killImpl,
                { 0x48, 0x8B, 0xC4,
                  0x44, 0x88, 0x48, 0x20 });
        }

        void InstallAVOEntryHooks()
        {
            if (!g_config.traceEntryCalls ||
                !g_runtime1170) {
                return;
            }

            if (g_targets.setBase) {
                logger::info(
                    "[entry-install] Skyrim::ActorValueOwner::SetBaseActorValue "
                    "target={} entry hook intentionally skipped; "
                    "vtable tracing remains active",
                    FormatAddress(g_targets.setBase));
            }

            InstallEntryHook(
                "Skyrim::ActorValueOwner::ModActorValue",
                g_targets.modAV,
                E_ModActorValue,
                g_entryOriginal.modAV,
                { 0x48, 0x89, 0x5C, 0x24, 0x08 });

            InstallEntryHook(
                "Skyrim::ActorValueOwner::RestoreActorValue",
                g_targets.restoreAV,
                E_RestoreActorValue,
                g_entryOriginal.restoreAV,
                { 0x48, 0x83, 0xEC, 0x38,
                  0x48, 0x81, 0xC1, 0x48,
                  0xFF, 0xFF, 0xFF });

            InstallEntryHook(
                "Skyrim::ActorValueOwner::SetActorValue",
                g_targets.setAV,
                E_SetActorValue,
                g_entryOriginal.setAV,
                { 0x48, 0x8B, 0x01,
                  0x48, 0xFF, 0x60, 0x20 });
        }

        void DescribeActorLayout(
            std::uintptr_t a_actorVTable)
        {
            static bool done = false;
            if (done) {
                return;
            }
            done = true;

            logger::info(
                "[layout] Actor primary vtable=0x{:X}",
                a_actorVTable);

            DescribeVTableSlot(
                "Actor::HandleHealthDamage",
                a_actorVTable,
                kActor_HandleHealthDamage);

            DescribeVTableSlot(
                "Actor::KillImpl",
                a_actorVTable,
                kActor_KillImpl);

            DescribeVTableSlot(
                "Actor::CheckClampDamageModifier",
                a_actorVTable,
                kActor_CheckClampDamageModifier);

            DescribeVTableSlot(
                "Actor::KillDying",
                a_actorVTable,
                kActor_KillDying);

            DescribeVTableSlot(
                "Actor::Resurrect",
                a_actorVTable,
                kActor_Resurrect);
        }

        void DescribeAVOLayout(
            std::uintptr_t a_liveAVOVTable)
        {
            static bool done = false;
            if (done || !a_liveAVOVTable) {
                return;
            }
            done = true;

            static REL::Relocation<std::uintptr_t>
                canonicalAVO{
                    RE::VTABLE_ActorValueOwner[0]
                };

            logger::info(
                "[layout] canonical ActorValueOwner vtable=0x{:X}; "
                "live Actor::ActorValueOwner vtable=0x{:X}; "
                "actorToAVOOffset=0x{:X}",
                canonicalAVO.address(),
                a_liveAVOVTable,
                static_cast<std::uintptr_t>(
                    g_actorToAVOOffset));

            DescribeVTableSlot(
                "ActorValueOwner::GetActorValue",
                a_liveAVOVTable,
                kAVO_GetActorValue);

            DescribeVTableSlot(
                "ActorValueOwner::SetBaseActorValue",
                a_liveAVOVTable,
                kAVO_SetBaseActorValue);

            DescribeVTableSlot(
                "ActorValueOwner::ModActorValue",
                a_liveAVOVTable,
                kAVO_ModActorValue);

            DescribeVTableSlot(
                "ActorValueOwner::RestoreActorValue",
                a_liveAVOVTable,
                kAVO_RestoreActorValue);

            DescribeVTableSlot(
                "ActorValueOwner::SetActorValue",
                a_liveAVOVTable,
                kAVO_SetActorValue);
        }

        bool InstallOrRefreshTracing()
        {
            static REL::Relocation<std::uintptr_t>
                actorVTable{
                    RE::VTABLE_Actor[0]
                };

            const auto actorVT =
                actorVTable.address();

            ResolveActorTargets(actorVT);
            DescribeActorLayout(actorVT);

            EnsureVTableHook(
                actorVT,
                kActor_HandleHealthDamage,
                V_HandleHealthDamage,
                g_vtablePrev.handleHealth,
                "Actor::HandleHealthDamage");

            EnsureVTableHook(
                actorVT,
                kActor_KillImpl,
                V_KillImpl,
                g_vtablePrev.killImpl,
                "Actor::KillImpl");

            EnsureVTableHook(
                actorVT,
                kActor_CheckClampDamageModifier,
                V_CheckClampDamageModifier,
                g_vtablePrev.checkClamp,
                "Actor::CheckClampDamageModifier");

            EnsureVTableHook(
                actorVT,
                kActor_KillDying,
                V_KillDying,
                g_vtablePrev.killDying,
                "Actor::KillDying");

            EnsureVTableHook(
                actorVT,
                kActor_Resurrect,
                V_Resurrect,
                g_vtablePrev.resurrect,
                "Actor::Resurrect");

            InstallActorEntryHooks();

            const auto liveAVOVT =
                DiscoverLiveActorAVOVTable();

            if (!liveAVOVT) {
                logger::info(
                    "[layout] live Actor::ActorValueOwner "
                    "vtable unavailable; AVO tracing deferred");
                return true;
            }

            if (g_liveActorAVOVTable != 0 &&
                g_liveActorAVOVTable != liveAVOVT) {
                logger::warn(
                    "[layout] live Actor::ActorValueOwner vtable "
                    "changed from 0x{:X} to 0x{:X}",
                    g_liveActorAVOVTable,
                    liveAVOVT);
            }

            g_liveActorAVOVTable =
                liveAVOVT;

            ResolveAVOTargets(liveAVOVT);
            DescribeAVOLayout(liveAVOVT);
            InstallAVOEntryHooks();

            EnsureVTableHook(
                liveAVOVT,
                kAVO_SetBaseActorValue,
                V_SetBaseActorValue,
                g_vtablePrev.setBase,
                "ActorValueOwner::SetBaseActorValue");

            EnsureVTableHook(
                liveAVOVT,
                kAVO_ModActorValue,
                V_ModActorValue,
                g_vtablePrev.modAV,
                "ActorValueOwner::ModActorValue");

            EnsureVTableHook(
                liveAVOVT,
                kAVO_RestoreActorValue,
                V_RestoreActorValue,
                g_vtablePrev.restoreAV,
                "ActorValueOwner::RestoreActorValue");

            EnsureVTableHook(
                liveAVOVT,
                kAVO_SetActorValue,
                V_SetActorValue,
                g_vtablePrev.setAV,
                "ActorValueOwner::SetActorValue");

            return true;
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
                    spdlog::sinks::basic_file_sink_mt>(
                        path->string(),
                        true);

            auto log =
                std::make_shared<spdlog::logger>(
                    "global",
                    std::move(sink));

            log->set_level(spdlog::level::debug);
            log->flush_on(spdlog::level::debug);

            spdlog::set_default_logger(
                std::move(log));

            spdlog::set_pattern(
                "[%H:%M:%S.%e] [%l] %v");
        }

        void MessageHandler(
            SKSE::MessagingInterface::Message* a_message)
        {
            if (!a_message) {
                return;
            }

            switch (a_message->type) {
            case SKSE::MessagingInterface::kPostPostLoad:
                InstallOrRefreshTracing();
                break;

            case SKSE::MessagingInterface::kDataLoaded:
                RegisterHitEventSink();
                InstallOrRefreshTracing();

                if (auto* tasks =
                        SKSE::GetTaskInterface()) {
                    tasks->AddTask(
                        []() {
                            RegisterHitEventSink();
                            InstallOrRefreshTracing();
                        });
                }
                break;

            case SKSE::MessagingInterface::kPostLoadGame:
            case SKSE::MessagingInterface::kNewGame:
                if (auto* tasks =
                        SKSE::GetTaskInterface()) {
                    tasks->AddTask(
                        []() {
                            RegisterHitEventSink();
                            InstallOrRefreshTracing();
                        });
                }
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

        const auto runtimeString =
            a_skse->RuntimeVersion().string();

        g_runtime1170 =
            runtimeString == "1-6-1170-0";

        logger::info(
            "UniversalCombatArbiter PoC3 "
            "Hit Event + Function Entry Tracer loading; runtime {}",
            runtimeString);

        LoadConfig();

        if (!g_runtime1170) {
            logger::warn(
                "PoC3 entry-detour prologues are verified only for "
                "Skyrim 1.6.1170. Vtable and hit-event tracing will "
                "still run, but engine-entry detours are disabled.");
        }

        if (!g_pristine.Load()) {
            logger::critical(
                "Failed to read Skyrim executable for pristine "
                "vtable recovery; tracer disabled");
            return true;
        }

        SKSE::AllocTrampoline(1u << 12);

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
    return UCA::Initialize(a_skse);
}
