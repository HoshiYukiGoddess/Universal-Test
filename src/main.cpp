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
        constexpr std::size_t kActor_HandleHealthDamage = 0x104;
        constexpr std::size_t kActor_CheckClampDamageModifier = 0x127;
        constexpr std::size_t kAVO_ModActorValue = 0x05;

        struct Config
        {
            bool traceHitEvents{ true };
            bool traceVTableCalls{ true };
            bool traceEntryCalls{ true };
        };

        Config g_config;
        bool g_runtime1170{ false };
        bool g_tracingInstalled{ false };
        bool g_hitSinkRegistered{ false };

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

            logger::info(
                "PoC3.2 config: hitEvents={}, vtableCalls={}, entryCalls={}",
                g_config.traceHitEvents,
                g_config.traceVTableCalls,
                g_config.traceEntryCalls);
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

        __declspec(noinline)
        std::string CaptureStackSummary(std::size_t a_depth = 10)
        {
            constexpr std::size_t kMaxFrames = 16;
            std::array<void*, kMaxFrames> frames{};

            const auto requested =
                static_cast<ULONG>(
                    std::min<std::size_t>(
                        a_depth,
                        kMaxFrames));

            const auto captured =
                ::CaptureStackBackTrace(
                    2,
                    requested,
                    frames.data(),
                    nullptr);

            std::string out;

            for (USHORT i = 0; i < captured; ++i) {
                if (i != 0) {
                    out += " <- ";
                }

                out += FormatAddress(
                    reinterpret_cast<std::uintptr_t>(
                        frames[i]));
            }

            if (out.empty()) {
                out = "<unavailable>";
            }

            return out;
        }

        bool ShouldCaptureStack(
            volatile LONG& a_counter,
            LONG a_limit = 8)
        {
            return ::InterlockedIncrement(
                       &a_counter) <= a_limit;
        }

        volatile LONG g_handleStackCount = 0;
        volatile LONG g_clampStackCount = 0;
        volatile LONG g_modAVStackCount = 0;

        std::string MemoryBytes(std::uintptr_t a_address, std::size_t a_count)
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

        void EmitAbsoluteJump(std::uint8_t* a_dst, std::uintptr_t a_target)
        {
            static constexpr std::array<std::uint8_t, 6> prefix{
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00
            };

            std::memcpy(a_dst, prefix.data(), prefix.size());
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
                    a_slot * sizeof(std::uintptr_t);

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
                        static_cast<std::uintptr_t>(
                            section.VirtualAddress);

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

        using CheckClampDamageModifier_t =
            float (*)(RE::Actor*, RE::ActorValue, float);

        using ModActorValue_t =
            void (*)(RE::ActorValueOwner*, RE::ActorValue, float);

        struct VTableFunctions
        {
            HandleHealthDamage_t handleHealth{};
            CheckClampDamageModifier_t checkClamp{};
        };

        struct EntryFunctions
        {
            HandleHealthDamage_t handleHealth{};
            CheckClampDamageModifier_t checkClamp{};
            ModActorValue_t modAV{};
        };

        struct EngineTargets
        {
            std::uintptr_t handleHealth{};
            std::uintptr_t checkClamp{};
            std::uintptr_t modAV{};
        };

        VTableFunctions g_vtablePrev{};
        EntryFunctions g_entryOriginal{};
        EngineTargets g_targets{};

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
                    "VirtualProtect failed for "
                    "vtable=0x{:X}[0x{:X}]",
                    a_vtable,
                    a_slot);
                return nullptr;
            }

            const auto previous = *entry;

            *entry =
                reinterpret_cast<std::uintptr_t>(
                    a_hook);

            DWORD ignored = 0;

            ::VirtualProtect(
                entry,
                sizeof(*entry),
                oldProtect,
                &ignored);

            return reinterpret_cast<Fn>(previous);
        }

        template <class Fn>
        void InstallVTableHookOnce(
            std::uintptr_t a_vtable,
            std::size_t a_slot,
            Fn a_hook,
            Fn& a_previous,
            std::string_view a_label)
        {
            if (!g_config.traceVTableCalls ||
                !a_vtable ||
                !a_hook ||
                a_previous) {
                return;
            }

            const auto currentAddress =
                *reinterpret_cast<std::uintptr_t*>(
                    a_vtable +
                    a_slot * sizeof(void*));

            a_previous =
                WriteVFuncRaw(
                    a_vtable,
                    a_slot,
                    a_hook);

            logger::info(
                "[vhook] {} "
                "vtable=0x{:X}[0x{:X}] "
                "prev={} ours={}",
                a_label,
                a_vtable,
                a_slot,
                FormatAddress(currentAddress),
                FormatAddress(
                    reinterpret_cast<std::uintptr_t>(
                        a_hook)));
        }

        template <class Fn>
        bool InstallFiveByteEntryHook(
            std::string_view a_label,
            std::uintptr_t a_target,
            Fn a_hook,
            Fn& a_original)
        {
            if (!g_config.traceEntryCalls ||
                !g_runtime1170 ||
                a_original ||
                !a_target ||
                !a_hook) {
                return false;
            }

            static constexpr std::array<std::uint8_t, 5> expected{
                0x48, 0x89, 0x5C, 0x24, 0x08
            };

            const bool prefixOK =
                PrefixMatches(
                    a_target,
                    {
                        expected[0],
                        expected[1],
                        expected[2],
                        expected[3],
                        expected[4]
                    });

            logger::info(
                "[prologue] {} "
                "target={} prefixMatch={} bytes=[{}]",
                a_label,
                FormatAddress(a_target),
                prefixOK,
                MemoryBytes(a_target, 16));

            if (!prefixOK) {
                logger::warn(
                    "[entry-install] {} skipped because "
                    "the verified 1.6.1170 five-byte "
                    "prologue does not match",
                    a_label);
                return false;
            }

            auto& trampoline =
                SKSE::GetTrampoline();

            auto* gateway =
                static_cast<std::uint8_t*>(
                    trampoline.allocate(19));

            std::memcpy(
                gateway,
                reinterpret_cast<const void*>(a_target),
                5);

            EmitAbsoluteJump(
                gateway + 5,
                a_target + 5);

            a_original =
                reinterpret_cast<Fn>(gateway);

            (void)trampoline.write_branch<5>(
                a_target,
                a_hook);

            ::FlushInstructionCache(
                ::GetCurrentProcess(),
                reinterpret_cast<const void*>(a_target),
                5);

            logger::info(
                "[entry-install] {} "
                "target={} gateway=0x{:X} "
                "stolen=5 bytes",
                a_label,
                FormatAddress(a_target),
                reinterpret_cast<std::uintptr_t>(
                    gateway));

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
                *reinterpret_cast<const std::uintptr_t*>(
                    a_vtable +
                    a_slot * sizeof(void*));

            const auto pristine =
                g_pristine.ResolveVFunc(
                    a_vtable,
                    a_slot);

            logger::info(
                "[slot] {} "
                "vtable=0x{:X}[0x{:X}] "
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

                // Deliberately no Actor casts, no ActorValueOwner calls,
                // and no Health reads inside the hit callback.
                auto* target =
                    a_event->target.get();

                auto* cause =
                    a_event->cause.get();

                logger::info(
                    "[hit:{}] "
                    "targetPtr=0x{:X} "
                    "targetForm=0x{:08X} "
                    "causePtr=0x{:X} "
                    "causeForm=0x{:08X} "
                    "source=0x{:08X} "
                    "projectile=0x{:08X} "
                    "flags=0x{:02X} "
                    "tid={}",
                    NextTraceID(),
                    reinterpret_cast<std::uintptr_t>(
                        target),
                    target ?
                        target->GetFormID() :
                        0,
                    reinterpret_cast<std::uintptr_t>(
                        cause),
                    cause ?
                        cause->GetFormID() :
                        0,
                    a_event->source,
                    a_event->projectile,
                    static_cast<std::uint32_t>(
                        a_event->flags.underlying()),
                    ::GetCurrentThreadId());

                return RE::BSEventNotifyControl::kContinue;
            }
        };

        HitEventSink g_hitSink;

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

            logger::info(
                "[hit] TESHitEvent sink registered");
        }

        void V_HandleHealthDamage(
            RE::Actor* a_self,
            RE::Actor* a_attacker,
            float a_damage)
        {
            if (!g_vtablePrev.handleHealth) {
                return;
            }

            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            logger::info(
                "[vcall:{}] HandleHealthDamage "
                "selfPtr=0x{:X} "
                "selfForm=0x{:08X} "
                "attackerPtr=0x{:X} "
                "attackerForm=0x{:08X} "
                "input={} tid={} caller={}",
                NextTraceID(),
                reinterpret_cast<std::uintptr_t>(
                    a_self),
                a_self ?
                    a_self->GetFormID() :
                    0,
                reinterpret_cast<std::uintptr_t>(
                    a_attacker),
                a_attacker ?
                    a_attacker->GetFormID() :
                    0,
                a_damage,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            g_vtablePrev.handleHealth(
                a_self,
                a_attacker,
                a_damage);
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

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            logger::info(
                "[vcall:{}] "
                "CheckClampDamageModifier "
                "selfPtr=0x{:X} "
                "selfForm=0x{:08X} "
                "input={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(
                    a_self),
                a_self ?
                    a_self->GetFormID() :
                    0,
                a_delta,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            const auto result =
                g_vtablePrev.checkClamp(
                    a_self,
                    a_value,
                    a_delta);

            logger::info(
                "[vcall:{}] "
                "CheckClampDamageModifier "
                "result={}",
                id,
                result);

            return result;
        }

        void E_HandleHealthDamage(
            RE::Actor* a_self,
            RE::Actor* a_attacker,
            float a_damage)
        {
            if (!g_entryOriginal.handleHealth) {
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            logger::info(
                "[entry:{}] HandleHealthDamage "
                "selfPtr=0x{:X} "
                "selfForm=0x{:08X} "
                "attackerPtr=0x{:X} "
                "attackerForm=0x{:08X} "
                "input={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(
                    a_self),
                a_self ?
                    a_self->GetFormID() :
                    0,
                reinterpret_cast<std::uintptr_t>(
                    a_attacker),
                a_attacker ?
                    a_attacker->GetFormID() :
                    0,
                a_damage,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            if (ShouldCaptureStack(
                    g_handleStackCount)) {
                logger::info(
                    "[stack:{}] HandleHealthDamage {}",
                    id,
                    CaptureStackSummary());
            }

            g_entryOriginal.handleHealth(
                a_self,
                a_attacker,
                a_damage);
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

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            logger::info(
                "[entry:{}] "
                "CheckClampDamageModifier "
                "selfPtr=0x{:X} "
                "selfForm=0x{:08X} "
                "input={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(
                    a_self),
                a_self ?
                    a_self->GetFormID() :
                    0,
                a_delta,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            if (ShouldCaptureStack(
                    g_clampStackCount)) {
                logger::info(
                    "[stack:{}] CheckClampDamageModifier {}",
                    id,
                    CaptureStackSummary());
            }

            const auto result =
                g_entryOriginal.checkClamp(
                    a_self,
                    a_value,
                    a_delta);

            logger::info(
                "[entry:{}] "
                "CheckClampDamageModifier "
                "result={}",
                id,
                result);

            return result;
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

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<std::uintptr_t>(
                    _ReturnAddress());

            logger::info(
                "[av-entry:{}] ModActorValue(Health) "
                "ownerPtr=0x{:X} amount={} tid={} caller={}",
                id,
                reinterpret_cast<std::uintptr_t>(
                    a_self),
                a_amount,
                ::GetCurrentThreadId(),
                FormatAddress(caller));

            if (ShouldCaptureStack(
                    g_modAVStackCount)) {
                logger::info(
                    "[stack:{}] ModActorValue(Health) {}",
                    id,
                    CaptureStackSummary());
            }

            g_entryOriginal.modAV(
                a_self,
                a_value,
                a_amount);
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

            return *reinterpret_cast<
                const std::uintptr_t*>(avo);
        }

        void InspectAndResolveAVOModTarget()
        {
            const auto liveAVOVT =
                DiscoverLiveActorAVOVTable();

            if (!liveAVOVT) {
                logger::info(
                    "[av-layout] live Actor::ActorValueOwner "
                    "vtable unavailable; ModActorValue probe skipped");
                return;
            }

            const auto current =
                *reinterpret_cast<
                    const std::uintptr_t*>(
                        liveAVOVT +
                        kAVO_ModActorValue *
                            sizeof(void*));

            const auto pristine =
                g_pristine.ResolveVFunc(
                    liveAVOVT,
                    kAVO_ModActorValue);

            logger::info(
                "[av-layout] ModActorValue "
                "liveVTable=0x{:X}[0x{:X}] "
                "current={} pristine={} same={}",
                liveAVOVT,
                kAVO_ModActorValue,
                FormatAddress(current),
                pristine ?
                    FormatAddress(pristine) :
                    std::string{ "<unavailable>" },
                pristine != 0 &&
                    current == pristine);

            g_targets.modAV = pristine;
        }
        void InstallTracingOnce()
        {
            if (g_tracingInstalled) {
                return;
            }

            static REL::Relocation<std::uintptr_t>
                actorVTable{
                    RE::VTABLE_Actor[0]
                };

            const auto actorVT =
                actorVTable.address();

            logger::info(
                "[layout] Actor primary vtable=0x{:X}",
                actorVT);

            DescribeVTableSlot(
                "Actor::HandleHealthDamage",
                actorVT,
                kActor_HandleHealthDamage);

            DescribeVTableSlot(
                "Actor::CheckClampDamageModifier",
                actorVT,
                kActor_CheckClampDamageModifier);

            g_targets.handleHealth =
                g_pristine.ResolveVFunc(
                    actorVT,
                    kActor_HandleHealthDamage);

            g_targets.checkClamp =
                g_pristine.ResolveVFunc(
                    actorVT,
                    kActor_CheckClampDamageModifier);

            InspectAndResolveAVOModTarget();

            InstallVTableHookOnce(
                actorVT,
                kActor_HandleHealthDamage,
                V_HandleHealthDamage,
                g_vtablePrev.handleHealth,
                "Actor::HandleHealthDamage");

            InstallVTableHookOnce(
                actorVT,
                kActor_CheckClampDamageModifier,
                V_CheckClampDamageModifier,
                g_vtablePrev.checkClamp,
                "Actor::CheckClampDamageModifier");

            InstallFiveByteEntryHook(
                "Skyrim::Actor::HandleHealthDamage",
                g_targets.handleHealth,
                E_HandleHealthDamage,
                g_entryOriginal.handleHealth);

            InstallFiveByteEntryHook(
                "Skyrim::Actor::CheckClampDamageModifier",
                g_targets.checkClamp,
                E_CheckClampDamageModifier,
                g_entryOriginal.checkClamp);

            InstallFiveByteEntryHook(
                "Skyrim::ActorValueOwner::ModActorValue",
                g_targets.modAV,
                E_ModActorValue,
                g_entryOriginal.modAV);

            g_tracingInstalled = true;

            logger::info(
                "PoC3.2 Stack + AV Probe installed");
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
            SKSE::MessagingInterface::Message* a_message)
        {
            if (!a_message) {
                return;
            }

            switch (a_message->type) {
            case SKSE::MessagingInterface::kDataLoaded:
                RegisterHitEventSink();
                InstallTracingOnce();
                break;

            case SKSE::MessagingInterface::kPostLoadGame:
            case SKSE::MessagingInterface::kNewGame:
                // One-shot by design. Do not reinstall hooks later.
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

        const auto runtimeString =
            a_skse->RuntimeVersion().string();

        g_runtime1170 =
            runtimeString == "1-6-1170-0";

        logger::info(
            "UniversalCombatArbiter "
            "PoC3.2 Stack + AV Probe loading; runtime {}",
            runtimeString);

        LoadConfig();

        if (!g_runtime1170) {
            logger::warn(
                "Engine-entry tracing is enabled "
                "only on Skyrim 1.6.1170");
        }

        if (!g_pristine.Load()) {
            logger::critical(
                "Failed to read Skyrim executable "
                "for vtable recovery; plugin disabled");

            return true;
        }

        SKSE::AllocTrampoline(
            1u << 10);

        auto* messaging =
            SKSE::GetMessagingInterface();

        if (!messaging ||
            !messaging->RegisterListener(
                MessageHandler)) {

            logger::critical(
                "Could not register "
                "SKSE message listener");

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
