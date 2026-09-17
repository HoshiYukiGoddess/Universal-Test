#include "PCH.h"

#include <fmt/format.h>
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

        // ActorValueOwner virtual slots according to CommonLibSSE-NG.
        constexpr std::size_t kAVO_GetActorValue = 0x01;
        constexpr std::size_t kAVO_SetBaseActorValue = 0x04;
        constexpr std::size_t kAVO_ModActorValue = 0x05;
        constexpr std::size_t kAVO_RestoreActorValue = 0x06;
        constexpr std::size_t kAVO_SetActorValue = 0x07;

        struct Config
        {
            bool traceIntegrity{ true };
            bool traceActorValueCalls{ true };
            bool traceLifecycle{ true };
            bool traceHealthReads{ false };
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

        void LoadConfig()
        {
            g_config.traceIntegrity =
                ReadIniBool(
                    "bTraceIntegrity",
                    true);

            g_config.traceActorValueCalls =
                ReadIniBool(
                    "bTraceActorValueCalls",
                    true);

            g_config.traceLifecycle =
                ReadIniBool(
                    "bTraceLifecycle",
                    true);

            g_config.traceHealthReads =
                ReadIniBool(
                    "bTraceHealthReads",
                    false);

            logger::info(
                "Tracer config: integrity={}, "
                "actorValue={}, lifecycle={}, "
                "healthReads={}",
                g_config.traceIntegrity,
                g_config.traceActorValueCalls,
                g_config.traceLifecycle,
                g_config.traceHealthReads);
        }

        std::uint64_t NextTraceID()
        {
            static volatile LONG64 sequence = 0;

            return static_cast<std::uint64_t>(
                ::InterlockedIncrement64(
                    &sequence));
        }

        struct AddressInfo
        {
            std::uintptr_t address{};
            std::uintptr_t moduleBase{};
            std::uintptr_t offset{};

            std::string moduleName{
                "<non-module>"
            };
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
                    reinterpret_cast<const void*>(
                        a_address),
                    &mbi,
                    sizeof(mbi)) == 0 ||
                !mbi.AllocationBase) {

                return result;
            }

            result.moduleBase =
                reinterpret_cast<std::uintptr_t>(
                    mbi.AllocationBase);

            result.offset =
                a_address -
                result.moduleBase;

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
                DescribeAddress(
                    a_address);

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

        std::string BytesToHex(
            const std::byte* a_bytes,
            std::size_t a_count)
        {
            static constexpr char kHex[] =
                "0123456789ABCDEF";

            std::string out{};

            if (!a_bytes ||
                a_count == 0) {

                return out;
            }

            out.reserve(
                a_count * 3);

            for (std::size_t i = 0;
                 i < a_count;
                 ++i) {

                const auto value =
                    static_cast<unsigned char>(
                        a_bytes[i]);

                if (i != 0) {
                    out.push_back(' ');
                }

                out.push_back(
                    kHex[
                        (value >> 4) &
                        0x0F]);

                out.push_back(
                    kHex[
                        value &
                        0x0F]);
            }

            return out;
        }

        class PristineImage
        {
        public:
            bool Load()
            {
                const auto module =
                    ::GetModuleHandleW(
                        nullptr);

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
                        "Could not open Skyrim executable "
                        "on disk");
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
                    sizeof(
                        IMAGE_DOS_HEADER)) {

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
                    IMAGE_FIRST_SECTION(
                        nt);

                _sections.assign(
                    first,
                    first +
                        nt->FileHeader
                            .NumberOfSections);

                logger::info(
                    "Pristine executable loaded: "
                    "runtimeBase=0x{:X}, "
                    "preferredBase=0x{:X}, "
                    "imageSize=0x{:X}",
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
                    (a_slot *
                     sizeof(
                         std::uintptr_t));

                const auto fileOffset =
                    RvaToFileOffset(
                        entryRva);

                if (!fileOffset ||
                    *fileOffset +
                        sizeof(
                            std::uint64_t) >
                        _bytes.size()) {

                    return 0;
                }

                std::uint64_t preferredVA = 0;

                std::memcpy(
                    &preferredVA,
                    _bytes.data() +
                        *fileOffset,
                    sizeof(
                        preferredVA));

                if (preferredVA <
                        _preferredBase ||
                    preferredVA >=
                        (_preferredBase +
                         _sizeOfImage)) {

                    return 0;
                }

                return _runtimeBase +
                       static_cast<
                           std::uintptr_t>(
                               preferredVA -
                               _preferredBase);
            }

            [[nodiscard]]
            bool ReadRuntimeBytes(
                std::uintptr_t a_runtimeAddress,
                std::size_t a_count,
                std::vector<std::byte>&
                    a_out) const
            {
                a_out.clear();

                if (!_runtimeBase ||
                    !_sizeOfImage ||
                    a_runtimeAddress <
                        _runtimeBase) {

                    return false;
                }

                const auto rva =
                    a_runtimeAddress -
                    _runtimeBase;

                if (rva >=
                    _sizeOfImage) {

                    return false;
                }

                const auto fileOffset =
                    RvaToFileOffset(
                        rva);

                if (!fileOffset ||
                    *fileOffset +
                            a_count >
                        _bytes.size()) {

                    return false;
                }

                a_out.resize(
                    a_count);

                std::memcpy(
                    a_out.data(),
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

                    return static_cast<
                        std::size_t>(
                            a_rva);
                }

                for (const auto& section :
                     _sections) {

                    const auto begin =
                        static_cast<
                            std::uintptr_t>(
                                section
                                    .VirtualAddress);

                    const auto span =
                        static_cast<
                            std::uintptr_t>(
                                std::max(
                                    section
                                        .Misc
                                        .VirtualSize,
                                    section
                                        .SizeOfRawData));

                    if (a_rva >= begin &&
                        a_rva <
                            begin + span) {

                        const auto delta =
                            a_rva - begin;

                        if (delta >=
                            section
                                .SizeOfRawData) {

                            return std::nullopt;
                        }

                        return static_cast<
                            std::size_t>(
                                section
                                    .PointerToRawData +
                                delta);
                    }
                }

                return std::nullopt;
            }

            std::vector<std::byte>
                _bytes{};

            std::vector<
                IMAGE_SECTION_HEADER>
                _sections{};

            std::uintptr_t
                _runtimeBase{};

            std::uintptr_t
                _preferredBase{};

            std::uintptr_t
                _sizeOfImage{};

            std::uintptr_t
                _sizeOfHeaders{};
        };

        PristineImage g_pristine;

        using HandleHealthDamage_t =
            void (*)(
                RE::Actor*,
                RE::Actor*,
                float);

        using KillImpl_t =
            void (*)(
                RE::Actor*,
                RE::Actor*,
                float,
                bool,
                bool);

        using CheckClampDamageModifier_t =
            float (*)(
                RE::Actor*,
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

        using GetActorValue_t =
            float (*)(
                RE::ActorValueOwner*,
                RE::ActorValue);

        using SetBaseActorValue_t =
            void (*)(
                RE::ActorValueOwner*,
                RE::ActorValue,
                float);

        using ModActorValue_t =
            void (*)(
                RE::ActorValueOwner*,
                RE::ActorValue,
                float);

        using RestoreActorValue_t =
            void (*)(
                RE::ActorValueOwner*,
                RE::ACTOR_VALUE_MODIFIER,
                RE::ActorValue,
                float);

        using SetActorValue_t =
            void (*)(
                RE::ActorValueOwner*,
                RE::ActorValue,
                float);

        struct FunctionSet
        {
            HandleHealthDamage_t
                prevHandleHealth{};

            KillImpl_t
                prevKillImpl{};

            CheckClampDamageModifier_t
                prevCheckClamp{};

            KillDying_t
                prevKillDying{};

            Resurrect_t
                prevResurrect{};

            GetActorValue_t
                prevGetAV{};

            SetBaseActorValue_t
                prevSetBase{};

            ModActorValue_t
                prevModAV{};

            RestoreActorValue_t
                prevRestoreAV{};

            SetActorValue_t
                prevSetAV{};
        };

        FunctionSet g_fn;

        std::uintptr_t
            g_liveActorAVOVTable{};

        std::intptr_t
            g_actorToAVOOffset{};

        RE::Actor* ActorFromAVO(
            RE::ActorValueOwner* a_owner)
        {
            if (!a_owner) {
                return nullptr;
            }

            return reinterpret_cast<RE::Actor*>(
                reinterpret_cast<
                    std::uintptr_t>(
                        a_owner) -
                static_cast<
                    std::uintptr_t>(
                        g_actorToAVOOffset));
        }

        std::uint32_t ActorFormIDFromAVO(
            RE::ActorValueOwner* a_owner)
        {
            const auto* actor =
                ActorFromAVO(
                    a_owner);

            return actor ?
                actor->GetFormID() :
                0;
        }

        float ReadHealth(
            RE::ActorValueOwner* a_owner)
        {
            if (!a_owner) {
                return 0.0F;
            }

            if (g_fn.prevGetAV) {
                return g_fn.prevGetAV(
                    a_owner,
                    RE::ActorValue::kHealth);
            }

            return a_owner->GetActorValue(
                RE::ActorValue::kHealth);
        }

        float ReadHealth(
            RE::Actor* a_actor)
        {
            return a_actor ?
                ReadHealth(
                    a_actor
                        ->AsActorValueOwner()) :
                0.0F;
        }

        void InspectEntryBytes(
            std::string_view a_label,
            std::uintptr_t a_function)
        {
            if (!g_config.traceIntegrity ||
                !a_function) {

                return;
            }

            constexpr std::size_t
                kBytes = 16;

            std::vector<std::byte>
                disk{};

            if (!g_pristine.ReadRuntimeBytes(
                    a_function,
                    kBytes,
                    disk)) {

                logger::info(
                    "[integrity] {} "
                    "target={} "
                    "diskBytes=<unavailable>",
                    a_label,
                    FormatAddress(
                        a_function));

                return;
            }

            std::array<
                std::byte,
                kBytes>
                memory{};

            std::memcpy(
                memory.data(),
                reinterpret_cast<
                    const void*>(
                        a_function),
                memory.size());

            const bool same =
                std::memcmp(
                    memory.data(),
                    disk.data(),
                    kBytes) == 0;

            logger::info(
                "[integrity] {} "
                "target={} "
                "bytesEqual={} "
                "memory=[{}] "
                "disk=[{}]",
                a_label,
                FormatAddress(
                    a_function),
                same,
                BytesToHex(
                    memory.data(),
                    memory.size()),
                BytesToHex(
                    disk.data(),
                    disk.size()));
        }

        void DescribeVTableSlot(
            std::string_view a_label,
            std::uintptr_t a_vtable,
            std::size_t a_slot)
        {
            if (!a_vtable) {
                logger::warn(
                    "[slot] {} "
                    "vtable=<null>",
                    a_label);
                return;
            }

            const auto current =
                *reinterpret_cast<
                    const std::uintptr_t*>(
                        a_vtable +
                        a_slot *
                            sizeof(void*));

            const auto pristine =
                g_pristine.ResolveVFunc(
                    a_vtable,
                    a_slot);

            logger::info(
                "[slot] {} "
                "vtable=0x{:X}[0x{:X}] "
                "current={} "
                "pristine={} "
                "same={}",
                a_label,
                a_vtable,
                a_slot,
                FormatAddress(
                    current),
                pristine ?
                    FormatAddress(
                        pristine) :
                    std::string{
                        "<unavailable>"
                    },
                pristine != 0 &&
                    current == pristine);
        }

        void InspectPristineSlot(
            std::string_view a_label,
            std::uintptr_t a_vtable,
            std::size_t a_slot)
        {
            if (!a_vtable ||
                !g_config.traceIntegrity) {

                return;
            }

            const auto pristine =
                g_pristine.ResolveVFunc(
                    a_vtable,
                    a_slot);

            if (pristine) {
                InspectEntryBytes(
                    a_label,
                    pristine);
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
                reinterpret_cast<
                    std::uintptr_t*>(
                        a_vtable +
                        a_slot *
                            sizeof(void*));

            DWORD oldProtect = 0;

            if (!::VirtualProtect(
                    entry,
                    sizeof(*entry),
                    PAGE_READWRITE,
                    &oldProtect)) {

                logger::error(
                    "VirtualProtect failed "
                    "for vtable=0x{:X}[0x{:X}]",
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

        template <class Fn>
        void EnsureHook(
            std::uintptr_t a_vtable,
            std::size_t a_slot,
            Fn a_hook,
            Fn& a_previous,
            std::string_view a_label)
        {
            if (!a_vtable) {
                return;
            }

            const auto hookAddress =
                reinterpret_cast<
                    std::uintptr_t>(
                        a_hook);

            const auto currentAddress =
                *reinterpret_cast<
                    std::uintptr_t*>(
                        a_vtable +
                        a_slot *
                            sizeof(void*));

            if (currentAddress ==
                hookAddress) {

                return;
            }

            a_previous =
                WriteVFuncRaw(
                    a_vtable,
                    a_slot,
                    a_hook);

            logger::info(
                "[hook] {} "
                "vtable=0x{:X}[0x{:X}] "
                "prev={} ours={}",
                a_label,
                a_vtable,
                a_slot,
                FormatAddress(
                    reinterpret_cast<
                        std::uintptr_t>(
                            a_previous)),
                FormatAddress(
                    hookAddress));
        }

        void Hook_HandleHealthDamage(
            RE::Actor* a_self,
            RE::Actor* a_attacker,
            float a_damage)
        {
            if (!g_fn.prevHandleHealth) {
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] ENTER "
                "HandleHealthDamage "
                "self=0x{:08X} "
                "attacker=0x{:08X} "
                "input={} "
                "healthBefore={} "
                "tid={} caller={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                a_attacker ?
                    a_attacker->GetFormID() :
                    0,
                a_damage,
                before,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));

            g_fn.prevHandleHealth(
                a_self,
                a_attacker,
                a_damage);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] EXIT  "
                "HandleHealthDamage "
                "self=0x{:08X} "
                "healthAfter={} "
                "observedDelta={} "
                "dead={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                after,
                after - before,
                a_self ?
                    a_self->IsDead() :
                    false);
        }

        float Hook_CheckClampDamageModifier(
            RE::Actor* a_self,
            RE::ActorValue a_value,
            float a_delta)
        {
            if (!g_fn.prevCheckClamp) {
                return a_delta;
            }

            if (a_value !=
                    RE::ActorValue::kHealth ||
                !g_config
                    .traceActorValueCalls) {

                return g_fn.prevCheckClamp(
                    a_self,
                    a_value,
                    a_delta);
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            const auto result =
                g_fn.prevCheckClamp(
                    a_self,
                    a_value,
                    a_delta);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] "
                "CheckClampDamageModifier "
                "self=0x{:08X} "
                "input={} result={} "
                "healthBefore={} "
                "healthAfter={} "
                "tid={} caller={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                a_delta,
                result,
                before,
                after,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));

            return result;
        }

        void Hook_KillImpl(
            RE::Actor* a_self,
            RE::Actor* a_attacker,
            float a_damage,
            bool a_sendEvent,
            bool a_ragdollInstant)
        {
            if (!g_fn.prevKillImpl) {
                return;
            }

            if (!g_config.traceLifecycle) {
                g_fn.prevKillImpl(
                    a_self,
                    a_attacker,
                    a_damage,
                    a_sendEvent,
                    a_ragdollInstant);
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] ENTER "
                "KillImpl "
                "self=0x{:08X} "
                "attacker=0x{:08X} "
                "damage={} "
                "healthBefore={} "
                "sendEvent={} "
                "ragdoll={} "
                "tid={} caller={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                a_attacker ?
                    a_attacker->GetFormID() :
                    0,
                a_damage,
                before,
                a_sendEvent,
                a_ragdollInstant,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));

            g_fn.prevKillImpl(
                a_self,
                a_attacker,
                a_damage,
                a_sendEvent,
                a_ragdollInstant);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] EXIT  "
                "KillImpl "
                "self=0x{:08X} "
                "healthAfter={} "
                "observedDelta={} "
                "dead={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                after,
                after - before,
                a_self ?
                    a_self->IsDead() :
                    false);
        }

        void Hook_KillDying(
            RE::Actor* a_self)
        {
            if (!g_fn.prevKillDying) {
                return;
            }

            if (!g_config.traceLifecycle) {
                g_fn.prevKillDying(
                    a_self);
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] ENTER "
                "KillDying "
                "self=0x{:08X} "
                "healthBefore={} "
                "tid={} caller={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                before,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));

            g_fn.prevKillDying(
                a_self);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] EXIT  "
                "KillDying "
                "self=0x{:08X} "
                "healthAfter={} "
                "observedDelta={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                after,
                after - before);
        }

        void Hook_Resurrect(
            RE::Actor* a_self,
            bool a_resetInventory,
            bool a_attach3D)
        {
            if (!g_fn.prevResurrect) {
                return;
            }

            if (!g_config.traceLifecycle) {
                g_fn.prevResurrect(
                    a_self,
                    a_resetInventory,
                    a_attach3D);
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] ENTER "
                "Resurrect "
                "self=0x{:08X} "
                "healthBefore={} "
                "resetInventory={} "
                "attach3D={} "
                "tid={} caller={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                before,
                a_resetInventory,
                a_attach3D,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));

            g_fn.prevResurrect(
                a_self,
                a_resetInventory,
                a_attach3D);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] EXIT  "
                "Resurrect "
                "self=0x{:08X} "
                "healthAfter={} "
                "observedDelta={} "
                "dead={}",
                id,
                a_self ?
                    a_self->GetFormID() :
                    0,
                after,
                after - before,
                a_self ?
                    a_self->IsDead() :
                    false);
        }

        float Hook_GetActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value)
        {
            if (!g_fn.prevGetAV) {
                return 0.0F;
            }

            const auto result =
                g_fn.prevGetAV(
                    a_self,
                    a_value);

            if (a_value ==
                    RE::ActorValue::kHealth &&
                g_config.traceHealthReads) {

                const auto id =
                    NextTraceID();

                const auto caller =
                    reinterpret_cast<
                        std::uintptr_t>(
                            _ReturnAddress());

                logger::info(
                    "[trace:{}] "
                    "GetActorValue(Health) "
                    "actor=0x{:08X} "
                    "avo=0x{:X} "
                    "result={} "
                    "tid={} caller={}",
                    id,
                    ActorFormIDFromAVO(
                        a_self),
                    reinterpret_cast<
                        std::uintptr_t>(
                            a_self),
                    result,
                    ::GetCurrentThreadId(),
                    FormatAddress(
                        caller));
            }

            return result;
        }

        void Hook_SetBaseActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_fn.prevSetBase) {
                return;
            }

            if (a_value !=
                    RE::ActorValue::kHealth ||
                !g_config
                    .traceActorValueCalls) {

                g_fn.prevSetBase(
                    a_self,
                    a_value,
                    a_amount);
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            g_fn.prevSetBase(
                a_self,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] "
                "SetBaseActorValue(Health) "
                "actor=0x{:08X} "
                "avo=0x{:X} "
                "amount={} "
                "healthBefore={} "
                "healthAfter={} "
                "observedDelta={} "
                "tid={} caller={}",
                id,
                ActorFormIDFromAVO(
                    a_self),
                reinterpret_cast<
                    std::uintptr_t>(
                        a_self),
                a_amount,
                before,
                after,
                after - before,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));
        }

        void Hook_ModActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_fn.prevModAV) {
                return;
            }

            if (a_value !=
                    RE::ActorValue::kHealth ||
                !g_config
                    .traceActorValueCalls) {

                g_fn.prevModAV(
                    a_self,
                    a_value,
                    a_amount);
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            g_fn.prevModAV(
                a_self,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] "
                "ModActorValue(Health) "
                "actor=0x{:08X} "
                "avo=0x{:X} "
                "amount={} "
                "healthBefore={} "
                "healthAfter={} "
                "observedDelta={} "
                "tid={} caller={}",
                id,
                ActorFormIDFromAVO(
                    a_self),
                reinterpret_cast<
                    std::uintptr_t>(
                        a_self),
                a_amount,
                before,
                after,
                after - before,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));
        }

        void Hook_RestoreActorValue(
            RE::ActorValueOwner* a_self,
            RE::ACTOR_VALUE_MODIFIER
                a_modifier,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_fn.prevRestoreAV) {
                return;
            }

            if (a_value !=
                    RE::ActorValue::kHealth ||
                !g_config
                    .traceActorValueCalls) {

                g_fn.prevRestoreAV(
                    a_self,
                    a_modifier,
                    a_value,
                    a_amount);
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            g_fn.prevRestoreAV(
                a_self,
                a_modifier,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] "
                "RestoreActorValue(Health) "
                "actor=0x{:08X} "
                "avo=0x{:X} "
                "modifier={} "
                "amount={} "
                "healthBefore={} "
                "healthAfter={} "
                "observedDelta={} "
                "tid={} caller={}",
                id,
                ActorFormIDFromAVO(
                    a_self),
                reinterpret_cast<
                    std::uintptr_t>(
                        a_self),
                static_cast<std::int32_t>(
                    a_modifier),
                a_amount,
                before,
                after,
                after - before,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));
        }

        void Hook_SetActorValue(
            RE::ActorValueOwner* a_self,
            RE::ActorValue a_value,
            float a_amount)
        {
            if (!g_fn.prevSetAV) {
                return;
            }

            if (a_value !=
                    RE::ActorValue::kHealth ||
                !g_config
                    .traceActorValueCalls) {

                g_fn.prevSetAV(
                    a_self,
                    a_value,
                    a_amount);
                return;
            }

            const auto id =
                NextTraceID();

            const auto caller =
                reinterpret_cast<
                    std::uintptr_t>(
                        _ReturnAddress());

            const auto before =
                ReadHealth(
                    a_self);

            g_fn.prevSetAV(
                a_self,
                a_value,
                a_amount);

            const auto after =
                ReadHealth(
                    a_self);

            logger::info(
                "[trace:{}] "
                "SetActorValue(Health) "
                "actor=0x{:08X} "
                "avo=0x{:X} "
                "amount={} "
                "healthBefore={} "
                "healthAfter={} "
                "observedDelta={} "
                "tid={} caller={}",
                id,
                ActorFormIDFromAVO(
                    a_self),
                reinterpret_cast<
                    std::uintptr_t>(
                        a_self),
                a_amount,
                before,
                after,
                after - before,
                ::GetCurrentThreadId(),
                FormatAddress(
                    caller));
        }

        std::uintptr_t
        DiscoverLiveActorAVOVTable()
        {
            auto* player =
                RE::PlayerCharacter
                    ::GetSingleton();

            auto* avo =
                player ?
                    player
                        ->AsActorValueOwner() :
                    nullptr;

            if (!player ||
                !avo) {

                return 0;
            }

            g_actorToAVOOffset =
                static_cast<
                    std::intptr_t>(
                        reinterpret_cast<
                            std::uintptr_t>(
                                avo) -
                        reinterpret_cast<
                            std::uintptr_t>(
                                player));

            return *reinterpret_cast<
                const std::uintptr_t*>(
                    avo);
        }

        void DescribeInitialLayout(
            std::uintptr_t a_actorVTable,
            std::uintptr_t a_liveAVOVTable)
        {
            static bool
                actorDescribed = false;

            static bool
                avoDescribed = false;

            static REL::Relocation<
                std::uintptr_t>
                canonicalAVO{
                    RE::VTABLE_ActorValueOwner[0]
                };

            if (!actorDescribed) {
                actorDescribed = true;

                logger::info(
                    "[layout] Actor primary "
                    "vtable=0x{:X}",
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

            if (a_liveAVOVTable &&
                !avoDescribed) {

                avoDescribed = true;

                logger::info(
                    "[layout] canonical "
                    "ActorValueOwner "
                    "vtable=0x{:X}; "
                    "live Actor::ActorValueOwner "
                    "vtable=0x{:X}; "
                    "actorToAVOOffset=0x{:X}",
                    canonicalAVO.address(),
                    a_liveAVOVTable,
                    static_cast<
                        std::uintptr_t>(
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
        }

        void InspectCoreEntries(
            std::uintptr_t a_actorVTable,
            std::uintptr_t a_liveAVOVTable)
        {
            if (!g_config.traceIntegrity) {
                return;
            }

            InspectPristineSlot(
                "Actor::HandleHealthDamage",
                a_actorVTable,
                kActor_HandleHealthDamage);

            InspectPristineSlot(
                "Actor::KillImpl",
                a_actorVTable,
                kActor_KillImpl);

            InspectPristineSlot(
                "Actor::CheckClampDamageModifier",
                a_actorVTable,
                kActor_CheckClampDamageModifier);

            InspectPristineSlot(
                "Actor::KillDying",
                a_actorVTable,
                kActor_KillDying);

            InspectPristineSlot(
                "Actor::Resurrect",
                a_actorVTable,
                kActor_Resurrect);

            if (a_liveAVOVTable) {
                InspectPristineSlot(
                    "ActorValueOwner::GetActorValue",
                    a_liveAVOVTable,
                    kAVO_GetActorValue);

                InspectPristineSlot(
                    "ActorValueOwner::SetBaseActorValue",
                    a_liveAVOVTable,
                    kAVO_SetBaseActorValue);

                InspectPristineSlot(
                    "ActorValueOwner::ModActorValue",
                    a_liveAVOVTable,
                    kAVO_ModActorValue);

                InspectPristineSlot(
                    "ActorValueOwner::RestoreActorValue",
                    a_liveAVOVTable,
                    kAVO_RestoreActorValue);

                InspectPristineSlot(
                    "ActorValueOwner::SetActorValue",
                    a_liveAVOVTable,
                    kAVO_SetActorValue);
            }
        }

        bool InstallOrRefreshHooks()
        {
            static REL::Relocation<
                std::uintptr_t>
                actorVTable{
                    RE::VTABLE_Actor[0]
                };

            const auto actorVT =
                actorVTable.address();

            const auto liveAVOVT =
                DiscoverLiveActorAVOVTable();

            DescribeInitialLayout(
                actorVT,
                liveAVOVT);

            InspectCoreEntries(
                actorVT,
                liveAVOVT);

            EnsureHook(
                actorVT,
                kActor_HandleHealthDamage,
                Hook_HandleHealthDamage,
                g_fn.prevHandleHealth,
                "Actor::HandleHealthDamage");

            EnsureHook(
                actorVT,
                kActor_KillImpl,
                Hook_KillImpl,
                g_fn.prevKillImpl,
                "Actor::KillImpl");

            EnsureHook(
                actorVT,
                kActor_CheckClampDamageModifier,
                Hook_CheckClampDamageModifier,
                g_fn.prevCheckClamp,
                "Actor::CheckClampDamageModifier");

            EnsureHook(
                actorVT,
                kActor_KillDying,
                Hook_KillDying,
                g_fn.prevKillDying,
                "Actor::KillDying");

            EnsureHook(
                actorVT,
                kActor_Resurrect,
                Hook_Resurrect,
                g_fn.prevResurrect,
                "Actor::Resurrect");

            if (!liveAVOVT) {
                logger::warn(
                    "[layout] live "
                    "Actor::ActorValueOwner "
                    "vtable not available yet; "
                    "AVO hooks deferred");

                return true;
            }

            if (g_liveActorAVOVTable != 0 &&
                g_liveActorAVOVTable !=
                    liveAVOVT) {

                logger::warn(
                    "[layout] live "
                    "Actor::ActorValueOwner "
                    "vtable changed from "
                    "0x{:X} to 0x{:X}; "
                    "not replacing existing "
                    "previous pointers",
                    g_liveActorAVOVTable,
                    liveAVOVT);

                return true;
            }

            g_liveActorAVOVTable =
                liveAVOVT;

            const auto currentGetAV =
                *reinterpret_cast<
                    std::uintptr_t*>(
                        liveAVOVT +
                        kAVO_GetActorValue *
                            sizeof(void*));

            if (!g_config.traceHealthReads) {
                g_fn.prevGetAV =
                    reinterpret_cast<
                        GetActorValue_t>(
                            currentGetAV);
            } else {
                EnsureHook(
                    liveAVOVT,
                    kAVO_GetActorValue,
                    Hook_GetActorValue,
                    g_fn.prevGetAV,
                    "ActorValueOwner::GetActorValue");
            }

            EnsureHook(
                liveAVOVT,
                kAVO_SetBaseActorValue,
                Hook_SetBaseActorValue,
                g_fn.prevSetBase,
                "ActorValueOwner::SetBaseActorValue");

            EnsureHook(
                liveAVOVT,
                kAVO_ModActorValue,
                Hook_ModActorValue,
                g_fn.prevModAV,
                "ActorValueOwner::ModActorValue");

            EnsureHook(
                liveAVOVT,
                kAVO_RestoreActorValue,
                Hook_RestoreActorValue,
                g_fn.prevRestoreAV,
                "ActorValueOwner::RestoreActorValue");

            EnsureHook(
                liveAVOVT,
                kAVO_SetActorValue,
                Hook_SetActorValue,
                g_fn.prevSetAV,
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
                kPostPostLoad:

                InstallOrRefreshHooks();
                break;

            case SKSE::MessagingInterface::
                kDataLoaded:

                InstallOrRefreshHooks();

                if (auto* tasks =
                        SKSE::
                            GetTaskInterface()) {

                    tasks->AddTask(
                        []() {
                            InstallOrRefreshHooks();
                        });
                }

                break;

            case SKSE::MessagingInterface::
                kPostLoadGame:

            case SKSE::MessagingInterface::
                kNewGame:

                if (auto* tasks =
                        SKSE::
                            GetTaskInterface()) {

                    tasks->AddTask(
                        []() {
                            InstallOrRefreshHooks();
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

        logger::info(
            "UniversalCombatArbiter "
            "PoC2 Health Pipeline Tracer "
            "loading; runtime {}",
            a_skse
                ->RuntimeVersion()
                .string());

        LoadConfig();

        if (!g_pristine.Load()) {
            logger::critical(
                "Failed to read pristine "
                "Skyrim executable; "
                "tracer disabled");

            return true;
        }

        auto* messaging =
            SKSE::
                GetMessagingInterface();

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
